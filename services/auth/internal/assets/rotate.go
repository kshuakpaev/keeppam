package assets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	_ "github.com/microsoft/go-mssqldb"
	"golang.org/x/crypto/ssh"

	"github.com/keeppam/auth/internal/store"
)

type RotateInput struct {
	// NewSecret optional; generated if empty. Never returned to client.
	NewSecret string `json:"new_secret"`
	// ApplyRemote when true attempts to change the credential on the target.
	ApplyRemote *bool `json:"apply_remote"`
	// RemoveOldKey for ssh_key remote rotation: drop previous pubkey after verify.
	RemoveOldKey bool `json:"remove_old_key"`
	// SkipPeerSync prevents cascading password_set peer updates (internal).
	SkipPeerSync bool `json:"-"`
}

type RotateResult struct {
	Account Account `json:"account"`
	Remote  bool    `json:"remote_applied"`
	Method  string  `json:"method"`
}

func (s *Service) RotateSecret(ctx context.Context, actorID, assetID, accountID uuid.UUID, in RotateInput, ip, ua string) (RotateResult, error) {
	asset, err := s.Get(ctx, assetID)
	if err != nil {
		return RotateResult{}, err
	}
	acc, err := s.getAccount(ctx, accountID)
	if err != nil {
		return RotateResult{}, err
	}
	if acc.AssetID != assetID {
		return RotateResult{}, fmt.Errorf("account does not belong to asset")
	}
	if acc.Status != "active" {
		return RotateResult{}, fmt.Errorf("account disabled")
	}
	if acc.CheckoutUserID != nil && *acc.CheckoutUserID != actorID && actorID != uuid.Nil {
		return RotateResult{}, fmt.Errorf("account checked out; check in (or force-checkin) before rotate")
	}

	method := acc.AuthMethod
	if method != "password" && method != "ssh_key" {
		return RotateResult{}, fmt.Errorf("unsupported auth_method %q", method)
	}

	canRemote := s.canRemoteRotate(asset, acc, method)
	applyRemote := canRemote
	if in.ApplyRemote != nil {
		applyRemote = *in.ApplyRemote
	}
	if applyRemote && !canRemote {
		return RotateResult{}, fmt.Errorf("remote rotation not available for protocol=%s method=%s; use apply_remote=false", asset.Protocol, method)
	}

	var oldSecret string
	if acc.HasSecret {
		creds, err := s.GetTargetCreds(ctx, assetID, accountID)
		if err != nil {
			return RotateResult{}, err
		}
		oldSecret = creds.Secret
	} else if applyRemote {
		return RotateResult{}, fmt.Errorf("account has no secret; cannot apply remote rotation")
	}

	newSecret, err := prepareNewSecret(method, strings.TrimSpace(in.NewSecret))
	if err != nil {
		return RotateResult{}, err
	}

	rotationID := store.NewID()
	var actorAny any
	if actorID != uuid.Nil {
		actorAny = actorID
	}
	fail := func(msg string, clearPending bool) (RotateResult, error) {
		if clearPending {
			_, _ = s.db.Pool.Exec(ctx, `DELETE FROM secret_rotation_pending WHERE account_id=$1`, accountID)
		}
		_, _ = s.db.Pool.Exec(ctx, `
			INSERT INTO secret_rotations (id, asset_id, account_id, actor_id, method, status, apply_remote, error, created_at)
			VALUES ($1,$2,$3,$4,$5,'failed',$6,$7,NOW())`,
			rotationID, assetID, accountID, actorAny, method, applyRemote, truncate(msg, 500))
		var actorPtr *uuid.UUID
		if actorID != uuid.Nil {
			actorPtr = &actorID
		}
		_ = s.aud.Record(ctx, actorPtr, "asset.account.secret_rotate.failure", "asset_account", accountID.String(), ip, ua, map[string]any{
			"asset_id": assetID.String(), "method": method, "apply_remote": applyRemote, "error": truncate(msg, 200),
		})
		return RotateResult{}, fmt.Errorf("%s", msg)
	}

	oldEnc, err := s.env.Encrypt([]byte(oldSecret))
	if err != nil {
		return fail("encrypt old: "+err.Error(), true)
	}
	newEnc, err := s.env.Encrypt([]byte(newSecret))
	if err != nil {
		return fail("encrypt new: "+err.Error(), true)
	}
	if applyRemote {
		// Checkpoint before remote change so crash mid-rotate can be reconciled (T-18/T-19).
		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO secret_rotation_pending (id, asset_id, account_id, method, old_secret_enc, new_secret_enc, remote_applied, actor_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,FALSE,$7,NOW(),NOW())
			ON CONFLICT (account_id) DO UPDATE SET
				id=$1, asset_id=$2, method=$4, old_secret_enc=$5, new_secret_enc=$6,
				remote_applied=FALSE, actor_id=$7, updated_at=NOW()`,
			rotationID, assetID, accountID, method, oldEnc, newEnc, actorAny)
		if err != nil {
			return fail("pending insert: "+err.Error(), true)
		}
		creds := TargetCreds{Account: acc, Asset: asset, Secret: oldSecret, AuthMethod: method}
		switch method {
		case "password":
			if err := s.applyRemotePassword(ctx, creds, newSecret); err != nil {
				return fail(err.Error(), true)
			}
		case "ssh_key":
			if err := s.applyRemoteSSHKey(ctx, creds, newSecret, in.RemoveOldKey); err != nil {
				return fail(err.Error(), true)
			}
		}
		_, _ = s.db.Pool.Exec(ctx, `
			UPDATE secret_rotation_pending SET remote_applied=TRUE, updated_at=NOW() WHERE account_id=$1`, accountID)
	}

	enc := newEnc
	now := time.Now().UTC()
	var nextRotate any
	if acc.RotateIntervalHours > 0 {
		nextRotate = now.Add(time.Duration(acc.RotateIntervalHours) * time.Hour)
	} else {
		nextRotate = nil
	}
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE asset_accounts SET secret_enc=$2, last_rotated_at=$3, next_rotate_at=$4, updated_at=$3 WHERE id=$1`,
		accountID, enc, now, nextRotate)
	if err != nil {
		// Keep pending (remote may already be new) for ReconcilePendingRotations.
		return fail("vault update: "+err.Error(), !applyRemote)
	}
	_, _ = s.db.Pool.Exec(ctx, `DELETE FROM secret_rotation_pending WHERE account_id=$1`, accountID)

	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO secret_rotations (id, asset_id, account_id, actor_id, method, status, apply_remote, error, created_at)
		VALUES ($1,$2,$3,$4,$5,'success',$6,'',NOW())`,
		rotationID, assetID, accountID, actorAny, method, applyRemote)
	var actorPtr *uuid.UUID
	if actorID != uuid.Nil {
		actorPtr = &actorID
	}
	_ = s.aud.Record(ctx, actorPtr, "asset.account.secret_rotated", "asset_account", accountID.String(), ip, ua, map[string]any{
		"asset_id": assetID.String(), "username": acc.Username, "method": method, "apply_remote": applyRemote,
	})

	out, err := s.getAccount(ctx, accountID)
	if err != nil {
		return RotateResult{}, err
	}
	if !in.SkipPeerSync && method == "password" {
		s.syncPeersAfterRotate(ctx, actorID, accountID, newSecret, applyRemote, ip, ua)
	}
	return RotateResult{Account: out, Remote: applyRemote, Method: method}, nil
}

func usesDirectoryPassword(asset Asset, acc Account) bool {
	return strings.TrimSpace(asset.ADPrivilegedGroupDN) != "" || strings.TrimSpace(acc.ADUserDN) != ""
}

func (s *Service) canRemoteRotate(asset Asset, acc Account, method string) bool {
	if method == "password" && s.ldapPass != nil && usesDirectoryPassword(asset, acc) {
		return true
	}
	return supportsRemoteRotation(asset.Protocol, method)
}

func supportsRemoteRotation(protocol, method string) bool {
	switch protocol {
	case "ssh":
		return method == "password" || method == "ssh_key"
	case "rdp", "vnc":
		return method == "password" || method == "ssh_key"
	case "postgres", "mysql", "mssql", "oracle":
		return method == "password"
	default:
		return false
	}
}

func prepareNewSecret(method, provided string) (string, error) {
	switch method {
	case "password":
		if provided == "" {
			return generatePassword(24)
		}
		if strings.ContainsAny(provided, "\n\r\x00") {
			return "", fmt.Errorf("secret must not contain newlines")
		}
		if len(provided) < 8 {
			return "", fmt.Errorf("secret too short (min 8)")
		}
		return provided, nil
	case "ssh_key":
		if provided == "" {
			return generateED25519PrivateKeyPEM()
		}
		if _, err := ssh.ParsePrivateKey([]byte(provided)); err != nil {
			return "", fmt.Errorf("invalid ssh private key: %w", err)
		}
		return provided, nil
	default:
		return "", fmt.Errorf("unsupported method")
	}
}

func (s *Service) applyRemotePassword(ctx context.Context, creds TargetCreds, newSecret string) error {
	if s.ldapPass != nil && usesDirectoryPassword(creds.Asset, creds.Account) {
		if err := s.ldapPass.ChangeAccountPassword(ctx, creds.Account, newSecret); err != nil {
			return fmt.Errorf("directory password change: %w", err)
		}
		return nil
	}
	switch creds.Asset.Protocol {
	case "ssh":
		client, err := s.DialSSH(ctx, creds)
		if err != nil {
			return fmt.Errorf("ssh dial: %w", err)
		}
		defer client.Close()
		if err := changeRemotePassword(client, creds.Account.Username, creds.Secret, newSecret); err != nil {
			return fmt.Errorf("remote password change: %w", err)
		}
		verify := creds
		verify.Secret = newSecret
		vClient, err := s.DialSSH(ctx, verify)
		if err != nil {
			_ = changeRemotePassword(client, creds.Account.Username, newSecret, creds.Secret)
			return fmt.Errorf("verify dial failed: %w", err)
		}
		_ = vClient.Close()
		return nil

	case "rdp", "vnc":
		client, err := s.dialManagementSSH(ctx, creds)
		if err != nil {
			return fmt.Errorf("management ssh :22 required for %s rotation: %w", creds.Asset.Protocol, err)
		}
		defer client.Close()
		if err := changeRemotePassword(client, creds.Account.Username, creds.Secret, newSecret); err != nil {
			if err2 := changeWindowsPassword(client, creds.Account.Username, newSecret); err2 != nil {
				return fmt.Errorf("remote password change: linux=%v; windows=%v", err, err2)
			}
		}
		return nil

	case "postgres":
		return rotatePostgresPassword(ctx, creds, newSecret)

	case "mysql":
		return s.rotateMySQLPassword(ctx, creds, newSecret)

	case "mssql":
		return rotateMSSQLPassword(ctx, creds, newSecret)

	case "oracle":
		return s.rotateOraclePassword(ctx, creds, newSecret)

	default:
		return fmt.Errorf("unsupported protocol %s", creds.Asset.Protocol)
	}
}

func (s *Service) applyRemoteSSHKey(ctx context.Context, creds TargetCreds, newPrivatePEM string, removeOld bool) error {
	client, err := s.dialSSHOrManagement(ctx, creds)
	if err != nil {
		return err
	}
	defer client.Close()

	newSigner, err := ssh.ParsePrivateKey([]byte(newPrivatePEM))
	if err != nil {
		return fmt.Errorf("parse new key: %w", err)
	}
	newPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner.PublicKey())))

	var oldPub string
	if creds.AuthMethod == "ssh_key" && creds.Secret != "" {
		if oldSigner, err := ssh.ParsePrivateKey([]byte(creds.Secret)); err == nil {
			oldPub = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(oldSigner.PublicKey())))
		}
	}

	if err := installAuthorizedKey(client, newPub); err != nil {
		return fmt.Errorf("install authorized_keys: %w", err)
	}

	verify := creds
	verify.AuthMethod = "ssh_key"
	verify.Secret = newPrivatePEM
	vClient, err := s.dialSSHOrManagement(ctx, verify)
	if err != nil {
		_ = removeAuthorizedKey(client, newPub)
		return fmt.Errorf("verify dial with new key failed: %w", err)
	}
	_ = vClient.Close()

	if removeOld && oldPub != "" && oldPub != newPub {
		_ = removeAuthorizedKey(client, oldPub)
	}
	return nil
}

func (s *Service) dialSSHOrManagement(ctx context.Context, creds TargetCreds) (*ssh.Client, error) {
	if creds.Asset.Protocol == "ssh" {
		return s.DialSSH(ctx, creds)
	}
	return s.dialManagementSSH(ctx, creds)
}

func (s *Service) dialManagementSSH(ctx context.Context, creds TargetCreds) (*ssh.Client, error) {
	mgmt := creds
	mgmt.Asset.Port = 22
	mgmt.Asset.Protocol = "ssh"
	return s.DialSSH(ctx, mgmt)
}

func rotatePostgresPassword(ctx context.Context, creds TargetCreds, newSecret string) error {
	host := net.JoinHostPort(creds.Asset.Address, strconv.Itoa(creds.Asset.Port))
	db := strings.TrimSpace(creds.Asset.DatabaseName)
	if db == "" {
		db = "postgres"
	}
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(creds.Account.Username, creds.Secret),
		Host:     host,
		Path:     "/" + db,
		RawQuery: "sslmode=disable",
	}
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return fmt.Errorf("postgres dial: %w", err)
	}
	defer conn.Close(ctx)

	ident := pgQuoteIdent(creds.Account.Username)
	if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER USER %s WITH PASSWORD %s", ident, pgQuoteLiteral(newSecret))); err != nil {
		return fmt.Errorf("ALTER USER: %w", err)
	}

	vu := *u
	vu.User = url.UserPassword(creds.Account.Username, newSecret)
	vconn, err := pgx.Connect(ctx, vu.String())
	if err != nil {
		_, _ = conn.Exec(ctx, fmt.Sprintf("ALTER USER %s WITH PASSWORD %s", ident, pgQuoteLiteral(creds.Secret)))
		return fmt.Errorf("verify dial failed: %w", err)
	}
	_ = vconn.Close(ctx)
	return nil
}

func (s *Service) rotateMySQLPassword(ctx context.Context, creds TargetCreds, newSecret string) error {
	client, err := s.dialManagementSSH(ctx, creds)
	if err != nil {
		return fmt.Errorf("mysql rotation needs SSH :22 on host: %w (or apply_remote=false)", err)
	}
	defer client.Close()

	user := shellQuote(creds.Account.Username)
	alter := fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", mysqlQuoteIdent(creds.Account.Username), mysqlQuoteLiteral(newSecret))
	script := "export MYSQL_PWD=" + shellQuote(creds.Secret) + "\n" +
		"mysql -u " + user + " -e " + shellQuote(alter) + "\n"

	_, stderr, err := sshRun(client, "bash -lc "+shellQuote(script))
	if err != nil {
		change := fmt.Sprintf("SET PASSWORD FOR %s = PASSWORD(%s)", mysqlQuoteIdent(creds.Account.Username), mysqlQuoteLiteral(newSecret))
		script2 := "export MYSQL_PWD=" + shellQuote(creds.Secret) + "\n" +
			"mysql -u " + user + " -e " + shellQuote(change) + "\n"
		_, stderr2, err2 := sshRun(client, "bash -lc "+shellQuote(script2))
		if err2 != nil {
			return fmt.Errorf("mysql password change: %v (%s); fallback: %v (%s)", err, truncate(stderr, 120), err2, truncate(stderr2, 120))
		}
	}
	return nil
}

func rotateMSSQLPassword(ctx context.Context, creds TargetCreds, newSecret string) error {
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
	u.RawQuery = q.Encode()

	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		return fmt.Errorf("mssql open: %w", err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(30 * time.Second)
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("mssql dial: %w", err)
	}
	stmt := fmt.Sprintf("ALTER LOGIN %s WITH PASSWORD = %s",
		mssqlQuoteIdent(creds.Account.Username), mssqlQuoteLiteral(newSecret))
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("ALTER LOGIN: %w", err)
	}
	vu := *u
	vu.User = url.UserPassword(creds.Account.Username, newSecret)
	vdb, err := sql.Open("sqlserver", vu.String())
	if err != nil {
		return fmt.Errorf("mssql verify open: %w", err)
	}
	defer vdb.Close()
	if err := vdb.PingContext(ctx); err != nil {
		rollback := fmt.Sprintf("ALTER LOGIN %s WITH PASSWORD = %s",
			mssqlQuoteIdent(creds.Account.Username), mssqlQuoteLiteral(creds.Secret))
		_, _ = db.ExecContext(ctx, rollback)
		return fmt.Errorf("verify dial failed: %w", err)
	}
	return nil
}

func mssqlQuoteIdent(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

func mssqlQuoteLiteral(s string) string {
	return "N'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func generatePassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+"
	if n < 12 {
		n = 12
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

func generateED25519PrivateKeyPEM() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "keeppam-rotated")
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(block)), nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func pgQuoteLiteral(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}

func mysqlQuoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}

func mysqlQuoteLiteral(s string) string {
	r := strings.ReplaceAll(s, `\`, `\\`)
	r = strings.ReplaceAll(r, `'`, `\'`)
	return `'` + r + `'`
}
