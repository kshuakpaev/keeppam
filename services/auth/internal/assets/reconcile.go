package assets

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// reconcileLock: only one API replica runs split-brain recovery.
const reconcileLock int64 = 87201607

// ReconcilePendingRotations finishes interrupted remote rotations (T-18/T-19).
func (s *Service) ReconcilePendingRotations(ctx context.Context) (int, error) {
	conn, err := s.db.Pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, reconcileLock).Scan(&got); err != nil {
		return 0, err
	}
	if !got {
		return 0, nil
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, reconcileLock)
	}()

	rows, err := conn.Query(ctx, `
		SELECT id, asset_id, account_id, method, old_secret_enc, new_secret_enc, remote_applied, actor_id
		FROM secret_rotation_pending
		WHERE updated_at < NOW() - INTERVAL '90 seconds'
		ORDER BY updated_at ASC
		LIMIT 20`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type pend struct {
		id                 uuid.UUID
		assetID, accountID uuid.UUID
		method             string
		oldEnc, newEnc     []byte
		remoteApplied      bool
		actorID            *uuid.UUID
	}
	var list []pend
	for rows.Next() {
		var p pend
		if err := rows.Scan(&p.id, &p.assetID, &p.accountID, &p.method, &p.oldEnc, &p.newEnc, &p.remoteApplied, &p.actorID); err != nil {
			return 0, err
		}
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	n := 0
	for _, p := range list {
		if err := s.reconcileOne(ctx, p.id, p.assetID, p.accountID, p.method, p.oldEnc, p.newEnc, p.remoteApplied, p.actorID); err != nil {
			slog.Warn("rotation reconcile", "account", p.accountID.String(), "err", err)
			continue
		}
		n++
	}
	return n, nil
}

func (s *Service) reconcileOne(ctx context.Context, pendingID, assetID, accountID uuid.UUID, method string, oldEnc, newEnc []byte, remoteApplied bool, actorID *uuid.UUID) error {
	asset, err := s.Get(ctx, assetID)
	if err != nil {
		return err
	}
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return err
	}
	oldSecret, err := s.env.Decrypt(oldEnc)
	if err != nil {
		return err
	}
	newSecret, err := s.env.Decrypt(newEnc)
	if err != nil {
		return err
	}

	if !remoteApplied {
		_, _ = s.db.Pool.Exec(ctx, `DELETE FROM secret_rotation_pending WHERE id=$1`, pendingID)
		_ = s.aud.Record(ctx, actorID, "asset.account.secret_rotate.reconciled", "asset_account", accountID.String(), "", "reconcile", map[string]any{
			"action": "drop_unapplied", "severity": "low",
		})
		return nil
	}

	newCreds := TargetCreds{Account: acc, Asset: asset, Secret: string(newSecret), AuthMethod: method}
	oldCreds := TargetCreds{Account: acc, Asset: asset, Secret: string(oldSecret), AuthMethod: method}

	if err := s.verifyTargetCreds(ctx, newCreds); err == nil {
		now := time.Now().UTC()
		var nextRotate any
		if acc.RotateIntervalHours > 0 {
			nextRotate = now.Add(time.Duration(acc.RotateIntervalHours) * time.Hour)
		}
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE asset_accounts SET secret_enc=$2, last_rotated_at=$3, next_rotate_at=$4, updated_at=$3 WHERE id=$1`,
			accountID, newEnc, now, nextRotate)
		if err != nil {
			return err
		}
		_, _ = s.db.Pool.Exec(ctx, `DELETE FROM secret_rotation_pending WHERE id=$1`, pendingID)
		_, _ = s.db.Pool.Exec(ctx, `
			INSERT INTO secret_rotations (id, asset_id, account_id, actor_id, method, status, apply_remote, error, created_at)
			VALUES ($1,$2,$3,$4,$5,'reconciled',TRUE,'vault committed after crash',NOW())`,
			pendingID, assetID, accountID, actorID, method)
		_ = s.aud.Record(ctx, actorID, "asset.account.secret_rotate.reconciled", "asset_account", accountID.String(), "", "reconcile", map[string]any{
			"action": "commit_new", "severity": "high",
		})
		return nil
	}

	if err := s.verifyTargetCreds(ctx, oldCreds); err == nil {
		_, _ = s.db.Pool.Exec(ctx, `DELETE FROM secret_rotation_pending WHERE id=$1`, pendingID)
		_ = s.aud.Record(ctx, actorID, "asset.account.secret_rotate.reconciled", "asset_account", accountID.String(), "", "reconcile", map[string]any{
			"action": "drop_remote_not_changed", "severity": "medium",
		})
		return nil
	}

	_ = s.aud.Record(ctx, actorID, "asset.account.secret_rotate.reconciled", "asset_account", accountID.String(), "", "reconcile", map[string]any{
		"action": "force_rotate", "severity": "critical",
	})
	_, _ = s.db.Pool.Exec(ctx, `DELETE FROM secret_rotation_pending WHERE id=$1`, pendingID)
	apply := true
	actor := uuid.Nil
	if actorID != nil {
		actor = *actorID
	}
	_, err = s.RotateSecret(ctx, actor, assetID, accountID, RotateInput{ApplyRemote: &apply, SkipPeerSync: true}, "", "reconcile")
	return err
}

func (s *Service) verifyTargetCreds(ctx context.Context, creds TargetCreds) error {
	if creds.AuthMethod == "ssh_key" {
		client, err := s.DialSSH(ctx, creds)
		if err != nil {
			return err
		}
		_ = client.Close()
		return nil
	}
	if usesDirectoryPassword(creds.Asset, creds.Account) {
		if v, ok := s.ldapPass.(interface {
			VerifyAccountPassword(ctx context.Context, acc Account, password string) error
		}); ok {
			return v.VerifyAccountPassword(ctx, creds.Account, creds.Secret)
		}
		// No verifier: prefer committing new vault secret when remote_applied.
		return nil
	}
	switch creds.Asset.Protocol {
	case "ssh":
		client, err := s.DialSSH(ctx, creds)
		if err != nil {
			return err
		}
		_ = client.Close()
		return nil
	case "rdp", "vnc":
		client, err := s.dialManagementSSH(ctx, creds)
		if err != nil {
			return err
		}
		_ = client.Close()
		return nil
	case "postgres":
		return verifyPostgresCreds(ctx, creds)
	case "mssql":
		return verifyMSSQLCreds(ctx, creds)
	case "mysql":
		client, err := s.dialManagementSSH(ctx, creds)
		if err != nil {
			return err
		}
		_ = client.Close()
		return nil
	default:
		return fmt.Errorf("verify unsupported protocol %s", creds.Asset.Protocol)
	}
}

func verifyPostgresCreds(ctx context.Context, creds TargetCreds) error {
	db := strings.TrimSpace(creds.Asset.DatabaseName)
	if db == "" {
		db = "postgres"
	}
	host := net.JoinHostPort(creds.Asset.Address, strconv.Itoa(creds.Asset.Port))
	if creds.Asset.Port <= 0 {
		host = net.JoinHostPort(creds.Asset.Address, "5432")
	}
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(creds.Account.Username, creds.Secret),
		Host:     host,
		Path:     "/" + db,
		RawQuery: "sslmode=disable&connect_timeout=5",
	}
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return err
	}
	_ = conn.Close(ctx)
	return nil
}

func verifyMSSQLCreds(ctx context.Context, creds TargetCreds) error {
	dbName := strings.TrimSpace(creds.Asset.DatabaseName)
	if dbName == "" {
		dbName = "master"
	}
	host := net.JoinHostPort(creds.Asset.Address, strconv.Itoa(creds.Asset.Port))
	if creds.Asset.Port <= 0 {
		host = net.JoinHostPort(creds.Asset.Address, "1433")
	}
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(creds.Account.Username, creds.Secret),
		Host:   host,
	}
	q := u.Query()
	q.Set("database", dbName)
	q.Set("encrypt", "disable")
	q.Set("dial timeout", "5")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return db.PingContext(cctx)
}
