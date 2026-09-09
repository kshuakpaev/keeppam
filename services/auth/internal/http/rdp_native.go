package httpapi

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/rdpgw"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) rdpPublicHost(r *http.Request) string {
	cfg := ""
	if s.rdp != nil {
		cfg = s.rdp.PublicHost
	}
	if strings.TrimSpace(cfg) == "" {
		cfg = s.cfg.RDPPublicHost
	}
	return clientFacingHost(cfg, r)
}

// assetRDPTarget is the host:port/user for a direct mstsc connection to the asset.
func assetRDPTarget(creds assets.TargetCreds) (host string, port int, user string) {
	host = strings.TrimSpace(creds.Asset.Address)
	if host == "" {
		host = strings.TrimSpace(creds.Asset.Hostname)
	}
	port = creds.Asset.Port
	if port <= 0 {
		port = 3389
	}
	user = strings.TrimSpace(creds.Account.Username)
	return host, port, user
}

// attachRDPNativeFiles always attaches a downloadable .rdp for Native Client.
// With a running freerdp-proxy: full address = KeepPAM gateway.
// Otherwise: full address = asset address (direct); vault password is not embedded.
func (s *Server) attachRDPNativeFiles(out map[string]any, r *http.Request, created sessionsvc.Session, creds assets.TargetCreds) {
	rdp := policy.RDPRedir{}
	if created.PolicySnapshot != nil {
		rdp = created.PolicySnapshot.RDP()
	}
	remote := rdpgw.RemoteAppOpts{
		Program: creds.Asset.RDPRemoteApp,
		Dir:     creds.Asset.RDPRemoteAppDir,
		Args:    creds.Asset.RDPRemoteAppArgs,
	}

	if s.rdp != nil && s.rdp.Enabled() {
		info, err := s.rdp.Prepare(r.Context(), created, created.PolicySnapshot, s.cfg.SessionTTL)
		if err == nil && info != nil && info.ProxyOK {
			host := s.rdpPublicHost(r)
			file := rdpgw.BuildRDPFile(host, info.Port, created.ID.String(), rdp, created.RDPWidth, created.RDPHeight, remote)
			filename := info.Filename
			if filename == "" {
				filename = fmt.Sprintf("keeppam-%s.rdp", created.ID.String()[:8])
			}
			addr := host
			if info.Port > 0 {
				addr = net.JoinHostPort(host, fmt.Sprintf("%d", info.Port))
			}
			out["rdp_token"] = info.Token
			out["rdp_addr"] = addr
			out["rdp_port"] = info.Port
			out["rdp_user"] = info.User
			out["rdp_hint"] = info.Hint
			out["rdp_file"] = file
			out["rdp_proxy"] = true
			out["rdp_filename"] = filename
			out["native_conn_file"] = file
			out["native_conn_filename"] = filename
			out["native_hint"] = info.Hint
			return
		}
		if err != nil {
			slog.Warn("native RDP Prepare failed; issuing direct asset .rdp", "err", err, "session", created.ID)
		}
	}

	host, port, user := assetRDPTarget(creds)
	filename := fmt.Sprintf("keeppam-%s.rdp", created.ID.String()[:8])
	hasSecret := strings.TrimSpace(creds.Secret) != ""
	file := rdpgw.BuildDirectRDPFile(host, port, user, rdp, created.RDPWidth, created.RDPHeight, !hasSecret, remote)
	addr := host
	if port > 0 {
		addr = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}
	launcherName := rdpgw.RDPLauncherFilename(filename)
	var launcher string
	var hint string
	if hasSecret {
		launcher = rdpgw.BuildRDPCredLauncherCMD(filename, host, user, creds.Secret)
		hint = fmt.Sprintf("Native Client: скачайте %s и %s в одну папку. Для входа с паролем запускайте %s (cmdkey+mstsc). Двойной клик по .rdp — без пароля в файле (mstsc так не умеет).", filename, launcherName, launcherName)
	} else {
		launcher = rdpgw.BuildRDPLauncherCMD(filename)
		hint = fmt.Sprintf("Native Client: %s → %s (учётка %s). Секрета в vault нет — mstsc запросит пароль.", filename, addr, user)
	}
	out["rdp_file"] = file
	out["rdp_filename"] = filename
	out["rdp_launcher"] = launcher
	out["rdp_launcher_filename"] = launcherName
	out["rdp_addr"] = addr
	out["rdp_port"] = port
	out["rdp_user"] = user
	out["rdp_hint"] = hint
	out["rdp_proxy"] = false
	out["native_conn_file"] = file
	out["native_conn_filename"] = filename
	out["native_launcher"] = launcher
	out["native_launcher_filename"] = launcherName
	out["native_hint"] = hint
}
