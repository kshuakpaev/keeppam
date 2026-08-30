package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keeppam/auth/internal/license"
)

func (s *Server) licensePath() string {
	if p := strings.TrimSpace(s.cfg.LicenseFile); p != "" {
		return p
	}
	return "/var/lib/keeppam/license.lic"
}

func (s *Server) currentLicense() license.File {
	s.licenseMu.RLock()
	defer s.licenseMu.RUnlock()
	return s.license
}

func (s *Server) setLicense(f license.File) {
	s.licenseMu.Lock()
	s.license = f
	s.licenseMu.Unlock()
	s.syncAssetQuota()
}

func (s *Server) syncAssetQuota() {
	s.assets.SetAssetQuota(func(ctx context.Context) error {
		n, err := s.assets.CountActive(ctx)
		if err != nil {
			return err
		}
		return s.currentLicense().AllowCreate(n, time.Now())
	})
	if s.sessionsvc != nil {
		s.sessionsvc.SetSessionQuota(func(ctx context.Context) error {
			n, err := s.sessionsvc.CountLive(ctx)
			if err != nil {
				return err
			}
			return s.currentLicense().AllowSession(n, time.Now())
		})
	}
}

func (s *Server) licenseUsage(ctx context.Context) (assetsN, sessionsN int, err error) {
	assetsN, err = s.assets.CountActive(ctx)
	if err != nil {
		return 0, 0, err
	}
	if s.sessionsvc != nil {
		sessionsN, err = s.sessionsvc.CountLive(ctx)
	}
	return assetsN, sessionsN, err
}

func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	n, sessN, err := s.licenseUsage(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := s.enrichLicenseStatus(s.currentLicense().Evaluate(n, sessN, time.Now()))
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) enrichLicenseStatus(st license.Status) license.Status {
	if st.Source == "ex2" || strings.HasSuffix(st.Source, ".lic") {
		st.Format = "ex2"
	} else if strings.HasSuffix(st.Source, ".json") || st.Source == "default" {
		st.Format = "json"
	}
	if host, err := license.HardwareFingerprint(); err == nil {
		st.HostFingerprint = host
	}
	return st
}

func (s *Server) handleLicenseFingerprint(w http.ResponseWriter, r *http.Request) {
	fp, err := license.HardwareFingerprint()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hardware_fingerprint": fp,
		"skip_hw":              s.cfg.LicenseSkipHW,
		"encryption_key_hint":  strings.HasPrefix(s.cfg.LicenseEncryptionKey, "your-32-byte"),
	})
}

func (s *Server) handleUploadLicense(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	const maxBody = 512 << 10
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	var raw []byte
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxBody); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid multipart")
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "missing file")
			return
		}
		defer file.Close()
		b, err := io.ReadAll(file)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "read file")
			return
		}
		raw = b
	} else {
		var body struct {
			LicenseFile string `json:"license_file"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body.LicenseFile))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid base64")
			return
		}
		raw = b
	}

	raw = license.NormalizeEx2Blob(raw)
	f, _, err := license.ParseEx2Blob(s.cfg.LicenseEncryptionKey, raw, s.cfg.LicenseSkipHW)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	path := s.licensePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	f.Source = path
	s.setLicense(f)
	_ = s.audit.Record(r.Context(), &sess.UserID, "license.uploaded", "license", path, s.clientIP(r), r.UserAgent(), map[string]any{
		"customer": f.Customer, "model": f.ResolvedModel(), "max_assets": f.MaxAssets, "max_users": f.MaxUsers, "expires": f.Expires,
	})

	n, sessN, _ := s.licenseUsage(r.Context())
	st := s.enrichLicenseStatus(f.Evaluate(n, sessN, time.Now()))
	writeJSON(w, http.StatusOK, st)
}
