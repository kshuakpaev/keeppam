package dbproxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keeppam/auth/internal/assets"
)

func TestParseOracleConnectKeepPAM(t *testing.T) {
	desc := `(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=pam)(PORT=11521))(CONNECT_DATA=(SERVICE_NAME=ORCL)(KEEPPAM_USER=alice+erpdb)(KEEPPAM_PASS=s3cret)))`
	c := parseOracleConnect(desc)
	if c.user != "alice+erpdb" || c.pass != "s3cret" || c.service != "ORCL" {
		t.Fatalf("got %+v", c)
	}
}

func TestParseOracleConnectTokenService(t *testing.T) {
	tok := strings.Repeat("ab", 16)
	desc := `(CONNECT_DATA=(SERVICE_NAME=` + tok + `)(USER=01900000-0000-7000-8000-000000000099))`
	c := parseOracleConnect(desc)
	if !looksLikeUUID(c.user) || c.pass != tok || c.service != "" {
		t.Fatalf("got %+v", c)
	}
}

func TestTNSRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeTNS(&buf, tnsAccept, tnsAcceptPayload()); err != nil {
		t.Fatal(err)
	}
	pkt, err := readTNS(&buf)
	if err != nil || pkt.typ != tnsAccept || len(pkt.payload) < 16 {
		t.Fatalf("typ=%d n=%d err=%v", pkt.typ, len(pkt.payload), err)
	}
}

func TestConnectDataFromPayload(t *testing.T) {
	desc := "(CONNECT_DATA=(SERVICE_NAME=XE))"
	payload := make([]byte, 62+len(desc))
	copy(payload[62:], desc)
	// length at 16, offset at 18 (relative to packet = payload index + 8)
	payload[16] = 0
	payload[17] = byte(len(desc))
	payload[18] = 0
	payload[19] = 70
	got := connectDataFromPayload(payload)
	if !strings.Contains(got, "SERVICE_NAME=XE") {
		t.Fatalf("got %q", got)
	}
}

func TestExtractSQLAndAuth(t *testing.T) {
	p := []byte("\x00\x00junk SELECT * FROM dual WHERE 1=1")
	if got := extractSQL(p); !strings.HasPrefix(got, "SELECT") {
		t.Fatalf("sql %q", got)
	}
	id := "01900000-0000-7000-8000-000000000099"
	tok := strings.Repeat("cd", 16)
	u, pw := extractOracleAuth([]byte("login " + id + " tok=" + tok))
	if u != id || pw != tok {
		t.Fatalf("user=%q pass=%q", u, pw)
	}
}

func TestOracleDSN(t *testing.T) {
	dsn := OracleDSN(assets.TargetCreds{
		Secret:  "s3cret",
		Account: assets.Account{Username: "scott"},
		Asset:   assets.Asset{Address: "10.1.2.3", Port: 1521, DatabaseName: "ORCL"},
	}, "ORCL")
	if !strings.Contains(dsn, "10.1.2.3") || !strings.Contains(dsn, "1521") {
		t.Fatalf("dsn %s", dsn)
	}
}

func TestIsSQLProtocolOracle(t *testing.T) {
	if !IsSQLProtocol("oracle") || UsesEphemeralDBRole("oracle") {
		t.Fatal("oracle flags")
	}
	if ResolveDatabase("oracle", "", "") != "ORCL" {
		t.Fatal("default service")
	}
}
