package settings

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/markeytos/radius-client/src/eap"
	mkradius "github.com/markeytos/radius-client/src/radius"
)

const (
	RadiusAuthPAP     = "pap"
	RadiusAuthEapTTLS = "eap-ttls"
	RadiusAuthPEAP    = "peap"
)

func normalizeRadiusAuthMethod(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	switch m {
	case "", RadiusAuthPAP:
		return RadiusAuthPAP
	case RadiusAuthEapTTLS, "eap_ttls", "ttls":
		return RadiusAuthEapTTLS
	case RadiusAuthPEAP, "peap-mschapv2":
		return RadiusAuthPEAP
	default:
		return m
	}
}

func radiusTLSHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		return hostOnly
	}
	return h
}

func radiusRadsecAddr(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h
	}
	return net.JoinHostPort(h, "2083")
}

func writeTempPEM(prefix, content string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", prefix+"*.pem")
	if err != nil {
		return "", nil, err
	}
	if _, err := f.WriteString(strings.TrimSpace(content)); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

func (s *Service) authenticateRadiusExtended(ctx context.Context, cfg AuthSettings, secret, username, password, method string) (string, error) {
	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()

	timeout := clampRADIUSTimeout(cfg.RADIUSTimeoutSec)
	nas := strings.TrimSpace(cfg.RADIUSNASID)
	if nas == "" {
		nas = "keeppam"
	}
	sendattrs := mkradius.AttributeMap{
		mkradius.AttributeTypeNasIdentifier: {nas},
		mkradius.AttributeTypeServiceType:   {"Login-User"},
	}

	var conn net.Conn
	var sharedSecret string
	var err error

	if cfg.RADIUSRadsec {
		if strings.TrimSpace(cfg.RADIUSRadsecCAPEM) == "" || strings.TrimSpace(cfg.RADIUSRadsecClientPEM) == "" {
			return "", fmt.Errorf("radius_radsec_ca_pem and radius_radsec_client_pem required for RadSec")
		}
		caPath, cleanup, err := writeTempPEM("keeppam-radsec-ca-", cfg.RADIUSRadsecCAPEM)
		if err != nil {
			return "", err
		}
		cleanups = append(cleanups, cleanup)
		clientPath, cleanup2, err := writeTempPEM("keeppam-radsec-client-", cfg.RADIUSRadsecClientPEM)
		if err != nil {
			return "", err
		}
		cleanups = append(cleanups, cleanup2)
		conn, err = dialRadsec(ctx, radiusRadsecAddr(cfg.RADIUSHost), caPath, clientPath)
		if err != nil {
			return "", err
		}
		sharedSecret = "radsec"
	} else {
		conn, err = dialRadiusUDP(ctx, radiusAddr(cfg.RADIUSHost))
		if err != nil {
			return "", err
		}
		sharedSecret = secret
	}
	cleanups = append(cleanups, func() { _ = conn.Close() })

	mtu := mkradius.DatagramMaxLen
	sendattrs[mkradius.AttributeTypeFramedMtu] = []string{strconv.Itoa(mtu)}
	session, err := mkradius.NewAuthenticationSession(conn, sharedSecret, timeout, 0, 0, 3, mtu, sendattrs, nil)
	if err != nil {
		return "", err
	}

	switch method {
	case RadiusAuthPAP:
		if err := session.PAP(username, password); err != nil {
			return "", fmt.Errorf("invalid credentials")
		}
	default:
		if strings.TrimSpace(cfg.RADIUSEAPCAPEM) == "" {
			return "", fmt.Errorf("radius_eap_ca_pem required for %s", method)
		}
		caPath, cleanup, err := writeTempPEM("keeppam-radius-eap-ca-", cfg.RADIUSEAPCAPEM)
		if err != nil {
			return "", err
		}
		cleanups = append(cleanups, cleanup)
		serverName := radiusTLSHost(cfg.RADIUSHost)
		anon := strings.TrimSpace(cfg.RADIUSEAPAnonymous)
		if anon == "" {
			anon = "anonymous"
		}
		eaptunnel := mkradius.NewEapAuthenticationTunnel(session, anon)
		if eaptunnel == nil {
			return "", fmt.Errorf("radius eap: tunnel init failed")
		}
		cleanups = append(cleanups, func() { _ = eaptunnel.Close() })

		switch method {
		case RadiusAuthEapTTLS:
			eapsession := eap.NewSession(eaptunnel, anon, false)
			eapttls, err := eap.CreateTTLS(eapsession, caPath, "1.2", serverName, "", cfg.RADIUSEAPInsecureTLS)
			if err != nil {
				return "", fmt.Errorf("radius eap-ttls: %w", err)
			}
			if err := eapttls.PAP(username, password); err != nil {
				return "", fmt.Errorf("invalid credentials")
			}
			if err := session.VerifyEAP(eapsession.RecvKey, eapsession.SendKey); err != nil {
				return "", fmt.Errorf("invalid credentials")
			}
		case RadiusAuthPEAP:
			eapsession := eap.NewSession(eaptunnel, anon, true)
			peap, err := eap.CreatePEAP(eapsession, caPath, "1.2", serverName, "", cfg.RADIUSEAPInsecureTLS)
			if err != nil {
				return "", fmt.Errorf("radius peap: %w", err)
			}
			inner := eap.NewSession(peap, anon, true)
			if err := inner.MsCHAPv2(username, password); err != nil {
				return "", fmt.Errorf("invalid credentials")
			}
			if err := session.VerifyEAP(inner.RecvKey, inner.SendKey); err != nil {
				return "", fmt.Errorf("invalid credentials")
			}
		default:
			return "", fmt.Errorf("unsupported radius_auth_method %q", method)
		}
	}

	return radiusSessionRoleAttr(session), nil
}

func dialRadiusUDP(ctx context.Context, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 {
		port = 1812
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func dialRadsec(ctx context.Context, addr, caPEM, clientPEM string) (net.Conn, error) {
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("invalid radsec CA PEM")
	}
	cert, err := tls.X509KeyPair([]byte(clientPEM), []byte(clientPEM))
	if err != nil {
		return nil, fmt.Errorf("radsec client cert: %w", err)
	}
	if !strings.ContainsRune(addr, ':') {
		addr = net.JoinHostPort(addr, "2083")
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("radsec dial: %w", err)
	}
	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	default:
	}
	return conn, nil
}

func radiusSessionRoleAttr(sess *mkradius.AuthenticationSession) string {
	dg := radiusSessionLastDatagram(sess)
	if dg == nil {
		return ""
	}
	if a := dg.Attributes.FirstOfType(mkradius.AttributeTypeFilterId); a != nil {
		return string(a.Value)
	}
	if a := dg.Attributes.FirstOfType(mkradius.AttributeTypeClass); a != nil {
		return string(a.Value)
	}
	return ""
}

func radiusSessionLastDatagram(sess *mkradius.AuthenticationSession) *mkradius.Datagram {
	if sess == nil {
		return nil
	}
	rv := reflect.ValueOf(sess).Elem()
	sf := rv.FieldByName("session")
	if !sf.IsValid() {
		return nil
	}
	lrd := sf.FieldByName("lastReadDatagram")
	if !lrd.IsValid() || lrd.IsNil() {
		return nil
	}
	dg, _ := lrd.Interface().(*mkradius.Datagram)
	return dg
}
