package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/sshgw"
)

func (s *Server) sshPublicHost(r *http.Request) string {
	return clientFacingHost(s.cfg.SSHPublicHost, r)
}

func (s *Server) sshConnOpts(r *http.Request, pamUser, assetName, accountName string) sshgw.ConnFileOpts {
	return sshgw.ConnFileOpts{
		PublicHost:   s.sshPublicHost(r),
		Port:         sshgw.ParseSSHPort(s.cfg.SSHAddr),
		PAMUser:      pamUser,
		AssetName:    assetName,
		AccountName:  accountName,
		IncludePutty: true,
	}
}

func (s *Server) attachSSHConnFile(out map[string]any, r *http.Request, pamUser, assetName, accountName string, wireUser, wirePass string) {
	opts := s.sshConnOpts(r, pamUser, assetName, accountName)
	opts.WireUser = strings.TrimSpace(wireUser)
	opts.WirePass = strings.TrimSpace(wirePass)
	cfgName := sshgw.ConnFilename(assetName, accountName)
	alias := sshgw.HostAlias(assetName, accountName)
	launcher := sshgw.BuildSSHLauncherCMD(opts)
	launcherName := sshgw.LauncherFilenameCMD(assetName, accountName)
	out["ssh_file"] = sshgw.BuildSSHConfigFile(opts)
	out["ssh_filename"] = cfgName
	out["ssh_hint"] = sshgw.BuildSSHHint(opts)
	out["ssh_addr"] = fmt.Sprintf("%s:%d", opts.PublicHost, opts.Port)
	out["ssh_launcher"] = launcher
	out["ssh_launcher_filename"] = launcherName
	out["ssh_launcher_sh"] = sshgw.BuildSSHLauncherSH(cfgName, alias)
	out["ssh_launcher_sh_filename"] = sshgw.LauncherFilenameSH(assetName, accountName)
	if opts.WirePass != "" {
		out["wire_token"] = opts.WirePass
		out["wire_user"] = opts.WireUser
	}
	out["native_conn_file"] = out["ssh_file"]
	out["native_conn_filename"] = cfgName
	out["native_launcher"] = launcher
	out["native_launcher_filename"] = launcherName
	out["native_hint"] = out["ssh_hint"]
}

// GET /api/v1/admin/assets/{id}/accounts/{accountId}/ssh.config
// ?bundle=1 → JSON with connection file + Native Client launchers (.cmd / .sh)
func (s *Server) handleDownloadSSHConfig(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	assetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	accountID, err := uuid.Parse(chi.URLParam(r, "accountId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return
	}
	if !s.ensureAssetLicenseVisible(w, r, assetID) {
		return
	}
	creds, err := s.assets.GetTargetCreds(r.Context(), assetID, accountID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if creds.Asset.Protocol != "ssh" {
		writeErr(w, http.StatusBadRequest, "asset is not ssh")
		return
	}
	opts := s.sshConnOpts(r, sess.Username, creds.Asset.Name, creds.Account.Username)
	cfgName := sshgw.ConnFilename(creds.Asset.Name, creds.Account.Username)
	alias := sshgw.HostAlias(creds.Asset.Name, creds.Account.Username)
	body := sshgw.BuildSSHConfigFile(opts)
	launcher := sshgw.BuildSSHLauncherCMD(opts)
	launcherName := sshgw.LauncherFilenameCMD(creds.Asset.Name, creds.Account.Username)
	if r.URL.Query().Get("bundle") == "1" {
		writeJSON(w, http.StatusOK, map[string]any{
			"native_conn_file":            body,
			"native_conn_filename":        cfgName,
			"native_launcher":             launcher,
			"native_launcher_filename":    launcherName,
			"native_launcher_sh":          sshgw.BuildSSHLauncherSH(cfgName, alias),
			"native_launcher_sh_filename": sshgw.LauncherFilenameSH(creds.Asset.Name, creds.Account.Username),
			"native_hint":                 sshgw.BuildSSHHint(opts),
			"ssh_file":                    body,
			"ssh_filename":                cfgName,
			"ssh_launcher":                launcher,
			"ssh_launcher_filename":       launcherName,
			"ssh_launcher_sh":             sshgw.BuildSSHLauncherSH(cfgName, alias),
			"ssh_launcher_sh_filename":    sshgw.LauncherFilenameSH(creds.Asset.Name, creds.Account.Username),
			"ssh_hint":                    sshgw.BuildSSHHint(opts),
			"ssh_addr":                    fmt.Sprintf("%s:%d", opts.PublicHost, opts.Port),
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, cfgName))
	_, _ = w.Write([]byte(body))
}

// GET /api/v1/admin/sessions/{id}/ssh.config — rebuild from session row
func (s *Server) handleDownloadSessionSSHConfig(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if row.UserID != sess.UserID && !rbac.HasPermission(sess.Permissions, "sessions.read") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if row.Protocol != "ssh" {
		writeErr(w, http.StatusBadRequest, "not an ssh session")
		return
	}
	pam := row.Username
	if pam == "" {
		pam = sess.Username
	}
	opts := s.sshConnOpts(r, pam, row.AssetName, row.AccountUsername)
	body := sshgw.BuildSSHConfigFile(opts)
	name := sshgw.ConnFilename(row.AssetName, row.AccountUsername)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write([]byte(body))
}
