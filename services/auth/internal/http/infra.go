package httpapi

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/keeppam/auth/internal/buildinfo"
	"github.com/keeppam/auth/internal/config"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/fips"
	"github.com/keeppam/auth/internal/obs"
	"github.com/keeppam/auth/internal/residency"
	"github.com/keeppam/auth/internal/sbom"
	"github.com/keeppam/auth/internal/spiffe"
)

func (s *Server) handleInfraStatus(w http.ResponseWriter, r *http.Request) {
	backend := s.cfg.RecordingsBackend
	if s.sessionsvc != nil && s.sessionsvc.RecordingStore() != nil {
		backend = s.sessionsvc.RecordingStore().Backend()
	}
	lockMode, lockDays := s.infraObjectLock()
	opaPkg := ""
	if s.policy != nil && s.policy.OPA() != nil {
		opaPkg = s.policy.OPA().Package()
	}
	mem := crypto.LastMemStatus()
	var res any
	compliant := true
	var risks []string
	if svc := s.residencySvc(); svc != nil {
		if st, err := svc.Get(r.Context()); err == nil {
			st.AttachCompliance(s.cfg.DataKeySource, s.cfg.S3Endpoint)
			res = st
			compliant = st.Compliant
			risks = st.Risks
		} else {
			compliant = residency.Compliant(residency.RegionKZ, true, s.cfg.DataKeySource, s.cfg.S3Endpoint)
			risks = residency.Risks(residency.RegionKZ, true, s.cfg.DataKeySource, s.cfg.S3Endpoint)
		}
	} else {
		compliant = residency.Compliant(residency.RegionKZ, true, s.cfg.DataKeySource, s.cfg.S3Endpoint)
		risks = residency.Risks(residency.RegionKZ, true, s.cfg.DataKeySource, s.cfg.S3Endpoint)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":             buildinfo.Version,
		"build_time":          buildinfo.BuildTime,
		"data_key_source":     s.cfg.DataKeySource,
		"recordings_backend":  backend,
		"recordings_dir":      s.cfg.RecordingsDir,
		"object_lock_mode":    lockMode,
		"object_lock_days":    lockDays,
		"worm_recordings":     backend == "s3" && lockMode != "",
		"tls_enabled":         s.cfg.TLSEnabled(),
		"mtls":                s.cfg.MTLSMode(),
		"s3_endpoint":         s.cfg.S3Endpoint,
		"s3_bucket":           s.cfg.S3Bucket,
		"s3_region":           s.cfg.S3Region,
		"s3_prefix":           s.cfg.S3Prefix,
		"http_addr":           s.cfg.HTTPAddr,
		"cookie_secure":       s.cfg.CookieSecure,
		"geoip_db":            s.cfg.GeoIPDB,
		"geoip_ready":         s.policy != nil && s.policy.Geo() != nil && s.policy.Geo().Loaded(),
		"geoip_type":          infraGeoType(s),
		"geoip_nodes":         infraGeoNodes(s),
		"trusted_proxies":     s.cfg.TrustedProxies,
		"opa_policy":          s.cfg.OPAPolicy,
		"opa_ready":           s.policy != nil && s.policy.OPA() != nil && s.policy.OPA().Ready(),
		"opa_package":         opaPkg,
		"spiffe_trust_domain": s.cfg.SPIFFETrustDomain,
		"spiffe_id":           s.infraSPIFFEID(),
		"spiffe_svid":         s.cfg.SPIFFESVIDFile != "",
		"spiffe_bundle":       s.cfg.SPIFFEBundleFile != "",
		"pkcs11_token_file":   s.cfg.PKCS11TokenFile,
		"pkcs11_module":       s.cfg.PKCS11Module,
		"pkcs11_helper":       s.cfg.PKCS11Helper != "",
		"pkcs11_label":        s.cfg.PKCS11Label,
		"pkcs11_uri":          s.cfg.PKCS11URI != "",
		"go_version":          fips.GoVersion(),
		"cgo_enabled":         fips.CGOEnabled(),
		"fips":                fips.Backend(),
		"fips_required":       s.cfg.FIPSRequired,
		"sbom_file":           s.cfg.SBOMFile != "",
		"sbom_components":     infraSBOMCount(),
		"otel_endpoint":       obs.NormalizeOTLPEndpoint(s.cfg.OTELEndpoint),
		"otel_ready":          obs.TracingEnabled(),
		"otel_via":            obs.OTELVia(s.cfg.OTELEndpoint),
		"coredump":            mem.CoreDump,
		"dumpable":            mem.Dumpable,
		"data_key_mlock":      mem.DataKeyMlock,
		"residency":           res,
		"residency_compliant": compliant,
		"residency_risks":     risks,
	})
}

func (s *Server) handleSBOM(w http.ResponseWriter, _ *http.Request) {
	bom, err := sbom.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, bom)
}

func infraSBOMCount() int {
	bom, err := sbom.Load()
	if err != nil {
		return 0
	}
	n := len(bom.Components)
	if bom.Metadata.Component != nil {
		n++
	}
	return n
}

func infraGeoType(s *Server) string {
	if s.policy == nil || s.policy.Geo() == nil {
		return ""
	}
	return s.policy.Geo().DatabaseType()
}

func infraGeoNodes(s *Server) uint {
	if s.policy == nil || s.policy.Geo() == nil {
		return 0
	}
	return s.policy.Geo().NodeCount()
}

func (s *Server) infraSPIFFEID() string {
	if s.cfg.SPIFFESVIDFile == "" {
		return ""
	}
	id, err := spiffe.LoadPEM(s.cfg.SPIFFESVIDFile, "")
	if err != nil || len(id.IDs) == 0 {
		return ""
	}
	return id.IDs[0]
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

// BuildTLSConfig loads optional client CA / SPIFFE bundle for mTLS (server cert is passed to ListenAndServeTLS).
func BuildTLSConfig(cfg config.Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	pool := x509.NewCertPool()
	hasCA := false
	if cfg.TLSClientCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("client CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA: no certificates parsed")
		}
		hasCA = true
	}
	if cfg.SPIFFEBundleFile != "" {
		pem, err := os.ReadFile(cfg.SPIFFEBundleFile)
		if err != nil {
			return nil, fmt.Errorf("spiffe bundle: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("spiffe bundle: no certificates parsed")
		}
		hasCA = true
	}
	if !hasCA {
		return tc, nil
	}
	tc.ClientCAs = pool
	if cfg.TLSRequireClientCert {
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tc.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tc, nil
}
