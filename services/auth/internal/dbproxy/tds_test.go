package dbproxy

import (
	"bytes"
	"testing"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

func TestLogin7RoundTrip(t *testing.T) {
	id := uuid.MustParse("01900000-0000-7000-8000-000000000099")
	raw := buildLogin7ForTest(id.String(), "wire-token-secret", "appdb")
	user, pass, db, err := parseLogin7(raw)
	if err != nil {
		t.Fatal(err)
	}
	if user != id.String() || pass != "wire-token-secret" || db != "appdb" {
		t.Fatalf("got user=%q pass=%q db=%q", user, pass, db)
	}
}

func TestSQLBatchText(t *testing.T) {
	stmt := "SELECT 1"
	if got := sqlBatchText(encodeUCS2(stmt)); got != stmt {
		t.Fatalf("got %q", got)
	}
}

func TestTDSObfuscate(t *testing.T) {
	s := "Pa$$w0rd"
	if decodeUCS2(tdsDeobfuscateBytes(tdsObfuscate(s))) != s {
		t.Fatal("obfuscate roundtrip")
	}
}

func TestPreloginAndErrorPackets(t *testing.T) {
	var buf bytes.Buffer
	if err := writePreloginResponse(&buf); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := readTDSMessage(bytes.NewReader(buf.Bytes()))
	if err != nil || typ != tdsPrelogin || len(payload) < 12 {
		t.Fatalf("prelogin typ=%d n=%d err=%v", typ, len(payload), err)
	}
	if payload[len(payload)-1] != tdsEncryptNotSup {
		t.Fatalf("encrypt %d", payload[len(payload)-1])
	}
	buf.Reset()
	if err := writeTDSMessage(&buf, tdsTabular, tdsError("denied")); err != nil {
		t.Fatal(err)
	}
	typ, payload, err = readTDSMessage(bytes.NewReader(buf.Bytes()))
	if err != nil || typ != tdsTabular || payload[0] != 0xAA {
		t.Fatalf("error token typ=%d first=%v err=%v", typ, payload, err)
	}
}

func TestIsSQLProtocol(t *testing.T) {
	if !IsSQLProtocol("mssql") || UsesEphemeralDBRole("mssql") {
		t.Fatal("mssql protocol flags")
	}
	if ResolveDatabase("mssql", "", "") != "master" {
		t.Fatal("default db")
	}
}

func TestMSSQLDSN(t *testing.T) {
	dsn := MSSQLDSN(assets.TargetCreds{
		Secret:  "s3cret",
		Account: assets.Account{Username: "sa"},
		Asset:   assets.Asset{Address: "10.1.2.3", Port: 1433},
	}, "appdb")
	if !bytes.Contains([]byte(dsn), []byte("sqlserver://")) || !bytes.Contains([]byte(dsn), []byte("database=appdb")) {
		t.Fatalf("dsn %s", dsn)
	}
}
