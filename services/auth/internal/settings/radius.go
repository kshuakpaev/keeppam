package settings

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type RADIUSIdentity struct {
	Username    string
	Email       string
	DisplayName string
	Role        string
}

func radiusAddr(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "1812")
}

func clampRADIUSTimeout(sec int) time.Duration {
	if sec < 1 {
		sec = 5
	}
	if sec > 30 {
		sec = 30
	}
	return time.Duration(sec) * time.Second
}

func radiusRoleFromFilter(filter, fallback string) string {
	f := strings.ToLower(strings.TrimSpace(filter))
	f = strings.TrimPrefix(f, "keeppam-")
	switch f {
	case "admin", "operator", "auditor", "security":
		return f
	}
	return fallback
}

func (s *Service) AuthenticateRADIUS(ctx context.Context, cfg AuthSettings, secretEnc []byte, username, password string) (RADIUSIdentity, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return RADIUSIdentity{}, fmt.Errorf("invalid credentials")
	}
	addr := radiusAddr(cfg.RADIUSHost)
	if addr == "" {
		return RADIUSIdentity{}, fmt.Errorf("radius is not configured")
	}
	secret, err := s.DecryptSecret(secretEnc)
	if err != nil {
		return RADIUSIdentity{}, err
	}
	if secret == "" {
		return RADIUSIdentity{}, fmt.Errorf("radius is not configured")
	}

	packet := radius.New(radius.CodeAccessRequest, []byte(secret))
	_ = rfc2865.UserName_SetString(packet, username)
	if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
		return RADIUSIdentity{}, fmt.Errorf("radius pap: %w", err)
	}
	nas := strings.TrimSpace(cfg.RADIUSNASID)
	if nas == "" {
		nas = "keeppam"
	}
	_ = rfc2865.NASIdentifier_SetString(packet, nas)
	_ = rfc2865.ServiceType_Set(packet, rfc2865.ServiceType_Value_LoginUser)

	exCtx, cancel := context.WithTimeout(ctx, clampRADIUSTimeout(cfg.RADIUSTimeoutSec))
	defer cancel()
	resp, err := radius.Exchange(exCtx, packet, addr)
	if err != nil {
		return RADIUSIdentity{}, fmt.Errorf("radius: %w", err)
	}
	if resp.Code != radius.CodeAccessAccept {
		return RADIUSIdentity{}, fmt.Errorf("invalid credentials")
	}

	role := strings.TrimSpace(cfg.RADIUSDefaultRole)
	if role == "" {
		role = "operator"
	}
	if fid := rfc2865.FilterID_GetString(resp); fid != "" {
		role = radiusRoleFromFilter(fid, role)
	}
	email := username
	if !strings.Contains(email, "@") {
		email = username + "@radius.local"
	}
	return RADIUSIdentity{
		Username:    username,
		Email:       email,
		DisplayName: username,
		Role:        role,
	}, nil
}

func RADIUSReady(cfg AuthSettings) bool {
	return cfg.Mode == "radius" && radiusAddr(cfg.RADIUSHost) != "" && cfg.HasRADIUSSecret
}
