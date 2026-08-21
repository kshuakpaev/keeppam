package settings

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/keeppam/auth/internal/crypto"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestRadiusAddr(t *testing.T) {
	if got := radiusAddr("10.1.1.8"); got != "10.1.1.8:1812" {
		t.Fatalf("got %q", got)
	}
	if got := radiusAddr("10.1.1.8:1645"); got != "10.1.1.8:1645" {
		t.Fatalf("got %q", got)
	}
}

func TestRadiusRoleFromFilter(t *testing.T) {
	if got := radiusRoleFromFilter("KeepPAM-admin", "operator"); got != "admin" {
		t.Fatalf("got %s", got)
	}
	if got := radiusRoleFromFilter("unknown", "operator"); got != "operator" {
		t.Fatalf("got %s", got)
	}
}

func TestAuthenticateRADIUS_PAP(t *testing.T) {
	secret := []byte("s3cret")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	srv := &radius.PacketServer{
		Handler: radius.HandlerFunc(func(w radius.ResponseWriter, r *radius.Request) {
			u := rfc2865.UserName_GetString(r.Packet)
			p := rfc2865.UserPassword_GetString(r.Packet)
			pkt := r.Response(radius.CodeAccessReject)
			if u == "alice" && p == "p@ss" {
				pkt = r.Response(radius.CodeAccessAccept)
				_ = rfc2865.FilterID_SetString(pkt, "keeppam-auditor")
			}
			_ = w.Write(pkt)
		}),
		SecretSource: radius.StaticSecretSource(secret),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()); _ = pc.Close() })
	time.Sleep(20 * time.Millisecond)

	env, err := crypto.NewEnvelope([]byte("keeppam-local-dev-key-32-bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{env: env}
	enc, err := svc.env.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	cfg := AuthSettings{RADIUSHost: addr, RADIUSNASID: "keeppam-test", RADIUSTimeoutSec: 3, RADIUSDefaultRole: "operator"}
	ident, err := svc.AuthenticateRADIUS(context.Background(), cfg, enc, "alice", "p@ss")
	if err != nil {
		t.Fatal(err)
	}
	if ident.Username != "alice" || ident.Role != "auditor" {
		t.Fatalf("%+v", ident)
	}
	if _, err := svc.AuthenticateRADIUS(context.Background(), cfg, enc, "alice", "nope"); err == nil {
		t.Fatal("expected reject")
	}
}

func TestRADIUSReady(t *testing.T) {
	if RADIUSReady(AuthSettings{Mode: "radius", RADIUSHost: "127.0.0.1"}) {
		t.Fatal("no secret")
	}
	if !RADIUSReady(AuthSettings{Mode: "radius", RADIUSHost: "127.0.0.1:1812", HasRADIUSSecret: true}) {
		t.Fatal("should be ready")
	}
}
