package adjit

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf16"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/settings"
	"github.com/keeppam/auth/internal/store"
)

// DirectoryConfig is the service-bind LDAP used for group membership + optional unicodePwd.
type DirectoryConfig struct {
	URL         string
	BindDN      string
	BindPass    string
	UserBaseDN  string
	UserFilter  string // with %s for username
	AttrUser    string
	StartTLS    bool
	InsecureTLS bool
}

type ResolveDirectory func(ctx context.Context) (DirectoryConfig, error)

type Service struct {
	db       *store.DB
	assets   *assets.Service
	sess     *sessionsvc.Service
	aud      *audit.Service
	resolve  ResolveDirectory
}

func New(db *store.DB, assetsSvc *assets.Service, sess *sessionsvc.Service, aud *audit.Service, resolve ResolveDirectory) *Service {
	return &Service{db: db, assets: assetsSvc, sess: sess, aud: aud, resolve: resolve}
}

// OnSessionStart adds the vault account user to the asset's privileged AD/LDAP group (if configured).
func (s *Service) OnSessionStart(ctx context.Context, sessionID uuid.UUID) {
	if err := s.join(ctx, sessionID); err != nil {
		slog.Warn("ad group jit join", "session", sessionID.String(), "err", err)
	}
}

// OnSessionEnd removes membership and optionally signals rotate (caller still runs MaybeRotateAfterSession).
func (s *Service) OnSessionEnd(ctx context.Context, sessionID uuid.UUID) {
	if err := s.leave(ctx, sessionID); err != nil {
		slog.Warn("ad group jit leave", "session", sessionID.String(), "err", err)
	}
}

func (s *Service) join(ctx context.Context, sessionID uuid.UUID) error {
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	asset, err := s.assets.Get(ctx, row.AssetID)
	if err != nil {
		return err
	}
	groupDN := strings.TrimSpace(asset.ADPrivilegedGroupDN)
	if groupDN == "" {
		return nil
	}
	acc, err := s.assets.GetAccount(ctx, row.AccountID)
	if err != nil {
		return err
	}
	dir, err := s.resolve(ctx)
	if err != nil {
		return s.failJoin(ctx, sessionID, row, groupDN, "", err)
	}
	userDN, err := s.resolveUserDN(dir, acc)
	if err != nil {
		return s.failJoin(ctx, sessionID, row, groupDN, "", err)
	}
	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO session_ad_memberships (session_id, asset_id, account_id, group_dn, user_dn, status)
		VALUES ($1,$2,$3,$4,$5,'pending')
		ON CONFLICT (session_id) DO UPDATE SET group_dn=$4, user_dn=$5, last_error=''`,
		sessionID, row.AssetID, row.AccountID, groupDN, userDN)

	if err := addGroupMember(dir, groupDN, userDN); err != nil {
		return s.failJoin(ctx, sessionID, row, groupDN, userDN, err)
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE session_ad_memberships SET status='joined', joined_at=NOW(), last_error='' WHERE session_id=$1`, sessionID)
	_ = s.sess.AddEvent(ctx, sessionID, "ad_group", map[string]any{
		"action": "join", "group_dn": groupDN, "user_dn": userDN,
	})
	_ = s.aud.Record(ctx, &row.UserID, "session.ad_group.join", "session", sessionID.String(), "", "adjit", map[string]any{
		"group_dn": groupDN, "user_dn": userDN, "account_id": row.AccountID.String(),
	})
	return nil
}

func (s *Service) failJoin(ctx context.Context, sessionID uuid.UUID, row sessionsvc.Session, groupDN, userDN string, err error) error {
	_, _ = s.db.Pool.Exec(ctx, `
		INSERT INTO session_ad_memberships (session_id, asset_id, account_id, group_dn, user_dn, status, last_error)
		VALUES ($1,$2,$3,$4,$5,'failed_join',$6)
		ON CONFLICT (session_id) DO UPDATE SET status='failed_join', last_error=$6, group_dn=$4, user_dn=$5`,
		sessionID, row.AssetID, row.AccountID, groupDN, userDN, truncateErr(err))
	_ = s.sess.AddEvent(ctx, sessionID, "ad_group", map[string]any{
		"action": "join_failed", "group_dn": groupDN, "user_dn": userDN, "error": truncateErr(err),
	})
	_ = s.aud.Record(ctx, &row.UserID, "session.ad_group.join_failed", "session", sessionID.String(), "", "adjit", map[string]any{
		"group_dn": groupDN, "error": truncateErr(err), "severity": "high",
	})
	return err
}

func (s *Service) leave(ctx context.Context, sessionID uuid.UUID) error {
	var groupDN, userDN, status string
	var accountID, assetID, userID uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `
		SELECT m.group_dn, m.user_dn, m.status, m.account_id, m.asset_id, s.user_id
		FROM session_ad_memberships m
		JOIN sessions s ON s.id = m.session_id
		WHERE m.session_id=$1`, sessionID).Scan(&groupDN, &userDN, &status, &accountID, &assetID, &userID)
	if err != nil {
		// No row: try from asset config for sessions that never joined
		row, gerr := s.sess.Get(ctx, sessionID)
		if gerr != nil {
			return nil
		}
		asset, aerr := s.assets.Get(ctx, row.AssetID)
		if aerr != nil || strings.TrimSpace(asset.ADPrivilegedGroupDN) == "" {
			return nil
		}
		// nothing recorded — nothing to leave
		return nil
	}
	if status == "left" {
		return nil
	}
	if status != "joined" && status != "failed_leave" {
		// never successfully joined
		return nil
	}
	dir, err := s.resolve(ctx)
	if err != nil {
		return s.failLeave(ctx, sessionID, userID, groupDN, userDN, err)
	}
	if err := removeGroupMember(dir, groupDN, userDN); err != nil {
		return s.failLeave(ctx, sessionID, userID, groupDN, userDN, err)
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE session_ad_memberships SET status='left', left_at=NOW(), last_error='' WHERE session_id=$1`, sessionID)
	_ = s.sess.AddEvent(ctx, sessionID, "ad_group", map[string]any{
		"action": "leave", "group_dn": groupDN, "user_dn": userDN,
	})
	_ = s.aud.Record(ctx, &userID, "session.ad_group.leave", "session", sessionID.String(), "", "adjit", map[string]any{
		"group_dn": groupDN, "user_dn": userDN,
	})
	return nil
}

func (s *Service) failLeave(ctx context.Context, sessionID, userID uuid.UUID, groupDN, userDN string, err error) error {
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE session_ad_memberships SET status='failed_leave', last_error=$2 WHERE session_id=$1`,
		sessionID, truncateErr(err))
	_ = s.sess.AddEvent(ctx, sessionID, "ad_group", map[string]any{
		"action": "leave_failed", "group_dn": groupDN, "user_dn": userDN, "error": truncateErr(err),
	})
	_ = s.aud.Record(ctx, &userID, "session.ad_group.leave_failed", "session", sessionID.String(), "", "adjit", map[string]any{
		"group_dn": groupDN, "error": truncateErr(err), "severity": "critical",
	})
	return err
}

func (s *Service) resolveUserDN(dir DirectoryConfig, acc assets.Account) (string, error) {
	if dn := strings.TrimSpace(acc.ADUserDN); dn != "" {
		return dn, nil
	}
	return lookupUserDN(dir, acc.Username)
}

func dial(dir DirectoryConfig) (*ldap.Conn, error) {
	if strings.TrimSpace(dir.URL) == "" {
		return nil, fmt.Errorf("ldap url not configured (Config → Auth LDAP)")
	}
	conn, err := ldap.DialURL(dir.URL)
	if err != nil {
		return nil, err
	}
	if dir.StartTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: dir.InsecureTLS} //nolint:gosec
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	if dir.BindDN != "" {
		if err := conn.Bind(dir.BindDN, dir.BindPass); err != nil {
			conn.Close()
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	return conn, nil
}

func lookupUserDN(dir DirectoryConfig, username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("empty username")
	}
	if dir.UserBaseDN == "" {
		return "", fmt.Errorf("ldap user base dn not configured")
	}
	conn, err := dial(dir)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	filter := dir.UserFilter
	if !strings.Contains(filter, "%s") {
		attr := dir.AttrUser
		if attr == "" {
			attr = "sAMAccountName"
		}
		filter = "(" + attr + "=%s)"
	}
	filter = fmt.Sprintf(filter, ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		dir.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter, []string{"dn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("ldap user not found: %s", username)
	}
	return res.Entries[0].DN, nil
}

func addGroupMember(dir DirectoryConfig, groupDN, userDN string) error {
	conn, err := dial(dir)
	if err != nil {
		return err
	}
	defer conn.Close()
	mod := ldap.NewModifyRequest(groupDN, nil)
	mod.Add("member", []string{userDN})
	if err := conn.Modify(mod); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
			return nil
		}
		// some directories use uniqueMember
		mod2 := ldap.NewModifyRequest(groupDN, nil)
		mod2.Add("uniqueMember", []string{userDN})
		if err2 := conn.Modify(mod2); err2 != nil {
			if ldap.IsErrorWithCode(err2, ldap.LDAPResultAttributeOrValueExists) {
				return nil
			}
			return fmt.Errorf("add member: %w (uniqueMember: %v)", err, err2)
		}
	}
	return nil
}

func removeGroupMember(dir DirectoryConfig, groupDN, userDN string) error {
	conn, err := dial(dir)
	if err != nil {
		return err
	}
	defer conn.Close()
	mod := ldap.NewModifyRequest(groupDN, nil)
	mod.Delete("member", []string{userDN})
	if err := conn.Modify(mod); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
			return nil
		}
		mod2 := ldap.NewModifyRequest(groupDN, nil)
		mod2.Delete("uniqueMember", []string{userDN})
		if err2 := conn.Modify(mod2); err2 != nil {
			if ldap.IsErrorWithCode(err2, ldap.LDAPResultNoSuchAttribute) {
				return nil
			}
			return fmt.Errorf("remove member: %w", err)
		}
	}
	return nil
}

// ChangeAccountPassword implements assets.LDAPPasswordChanger.
func (s *Service) ChangeAccountPassword(ctx context.Context, acc assets.Account, newPassword string) error {
	dir, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	dn, err := s.resolveUserDN(dir, acc)
	if err != nil {
		return err
	}
	return ChangePassword(dir, dn, newPassword)
}

// ChangePassword sets AD unicodePwd (LDAPS/StartTLS) or OpenLDAP userPassword.
func ChangePassword(dir DirectoryConfig, userDN, newPassword string) error {
	conn, err := dial(dir)
	if err != nil {
		return err
	}
	defer conn.Close()
	mod := ldap.NewModifyRequest(userDN, nil)
	mod.Replace("unicodePwd", []string{string(encodeUnicodePwd(newPassword))})
	if err := conn.Modify(mod); err != nil {
		mod2 := ldap.NewModifyRequest(userDN, nil)
		mod2.Replace("userPassword", []string{newPassword})
		if err2 := conn.Modify(mod2); err2 != nil {
			return fmt.Errorf("unicodePwd: %w; userPassword: %v", err, err2)
		}
	}
	return nil
}

func encodeUnicodePwd(password string) []byte {
	quoted := `"` + password + `"`
	u := utf16.Encode([]rune(quoted))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

func truncateErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 400 {
		return s[:400]
	}
	return s
}

// DirectoryFromAuthSettings maps portal LDAP settings to a directory connector.
func DirectoryFromAuthSettings(cfg settings.AuthSettings, bindPass string) DirectoryConfig {
	attr := cfg.LDAPAttrUsername
	if attr == "" {
		attr = "uid"
	}
	filter := cfg.LDAPUserFilter
	if filter == "" {
		filter = "(" + attr + "=%s)"
	}
	return DirectoryConfig{
		URL: cfg.LDAPURL, BindDN: cfg.LDAPBindDN, BindPass: bindPass,
		UserBaseDN: cfg.LDAPUserBaseDN, UserFilter: filter, AttrUser: attr,
		StartTLS: cfg.LDAPStartTLS, InsecureTLS: cfg.LDAPInsecureTLS,
	}
}
