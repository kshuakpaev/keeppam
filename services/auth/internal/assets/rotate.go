package assets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	canRemote := supportsRemoteRotation(asset.Protocol, method)
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
	fail := func(msg string) (RotateResult, error) {
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

	if applyRemote {
		creds := TargetCreds{Account: acc, Asset: asset, Secret: oldSecret, AuthMethod: method}
		switch method {
		case "password":
			if err := s.applyRemotePassword(ctx, creds, newSecret); err != nil {
				return fail(err.Error())
			}
		case "ssh_key":
			if err := s.applyRemoteSSHKey(ctx, creds, newSecret, in.RemoveOldKey); err != nil {
				return fail(err.Error())
			}
		}
	}

	enc, err := s.env.Encrypt([]byte(newSecret))
	if err != nil {
		return fail("encrypt: " + err.Error())
	}
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
		return fail("vault update: " + err.Error())
	}

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
	return RotateResult{Account: out, Remote: applyRemote, Method: method}, nil
}

func supportsRemoteRotation(protocol, method string) bool {
	switch protocol {
	case "ssh":
		return method == "password" || method == "ssh_key"
	case "rdp", "vnc":
		return method == "password" || method == "ssh_key"
	case "postgres", "mysql":
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
