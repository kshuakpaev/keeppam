package httpapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/keeppam/auth/internal/config"
)

func (s *Server) handleInfraStatus(w http.ResponseWriter, _ *http.Request) {
	backend := s.cfg.RecordingsBackend
	if s.sessionsvc != nil && s.sessionsvc.RecordingStore() != nil {
		backend = s.sessionsvc.RecordingStore().Backend()
	}
	lockMode, lockDays := s.infraObjectLock()
	writeJSON(w, http.StatusOK, map[string]any{
		"data_key_source":      s.cfg.DataKeySource,
		"recordings_backend":   backend,
		"recordings_dir":       s.cfg.RecordingsDir,
		"object_lock_mode":     lockMode,
		"object_lock_days":     lockDays,
		"worm_recordings":      backend == "s3" && lockMode != "",
		"tls_enabled":          s.cfg.TLSEnabled(),
		"mtls":                 s.cfg.MTLSMode(),
		"s3_endpoint":          s.cfg.S3Endpoint,
		"s3_bucket":            s.cfg.S3Bucket,
		"s3_region":            s.cfg.S3Region,
		"s3_prefix":            s.cfg.S3Prefix,
		"http_addr":            s.cfg.HTTPAddr,
		"cookie_secure":        s.cfg.CookieSecure,
	})
}

func (s *Server) infraObjectLock() (mode string, days int) {
	mode = s.cfg.S3ObjectLockMode
	days = s.cfg.S3ObjectLockDays
	if st := s.sessionsvc.RecordingStore(); st != nil {
		if m := st.ObjectLockMode(); m != "" {
			mode = m
		}
		if d := st.ObjectLockDays(); d > 0 {
			days = d
		}
	}
	return mode, days
}

// BuildTLSConfig loads optional client CA for mTLS (server cert is passed to ListenAndServeTLS).
func BuildTLSConfig(cfg config.Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSClientCAFile == "" {
		return tc, nil
	}
	pem, err := os.ReadFile(cfg.TLSClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("client CA: no certificates parsed")
	}
	tc.ClientCAs = pool
	if cfg.TLSRequireClientCert {
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tc.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tc, nil
}
