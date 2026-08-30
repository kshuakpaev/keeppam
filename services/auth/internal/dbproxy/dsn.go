package dbproxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/keeppam/auth/internal/assets"
	go_ora "github.com/sijms/go-ora/v2"
)

// ResolveDatabase picks session override, then asset field, then protocol default.
func ResolveDatabase(protocol, sessionDB, assetDB string) string {
	if s := strings.TrimSpace(sessionDB); s != "" {
		return s
	}
	if s := strings.TrimSpace(assetDB); s != "" {
		return s
	}
	if protocol == "postgres" {
		return "postgres"
	}
	if protocol == "mssql" {
		return "master"
	}
	if protocol == "oracle" {
		return "ORCL"
	}
	return ""
}

func PostgresDSN(creds assets.TargetCreds, database string) string {
	db := strings.TrimSpace(database)
	if db == "" {
		db = "postgres"
	}
	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(creds.Account.Username, creds.Secret),
		Host:     fmt.Sprintf("%s:%d", creds.Asset.Address, creds.Asset.Port),
		Path:     "/" + db,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

func MySQLDSN(creds assets.TargetCreds, database string) string {
	db := strings.TrimSpace(database)
	base := fmt.Sprintf("%s:%s@tcp(%s:%d)/",
		creds.Account.Username, creds.Secret, creds.Asset.Address, creds.Asset.Port)
	if db == "" {
		return base + "?parseTime=true&timeout=15s"
	}
	return base + db + "?parseTime=true&timeout=15s"
}

func MSSQLDSN(creds assets.TargetCreds, database string) string {
	db := strings.TrimSpace(database)
	if db == "" {
		db = "master"
	}
	u := &url.URL{
		Scheme: "sqlserver",
		User:   url.UserPassword(creds.Account.Username, creds.Secret),
		Host:   fmt.Sprintf("%s:%d", creds.Asset.Address, creds.Asset.Port),
	}
	q := url.Values{}
	q.Set("database", db)
	q.Set("encrypt", "true")
	q.Set("TrustServerCertificate", "true")
	q.Set("dial timeout", "15")
	u.RawQuery = q.Encode()
	return u.String()
}

func OracleDSN(creds assets.TargetCreds, service string) string {
	svc := strings.TrimSpace(service)
	if svc == "" {
		svc = "ORCL"
	}
	port := creds.Asset.Port
	if port <= 0 {
		port = 1521
	}
	opts := map[string]string{}
	if strings.EqualFold(strings.TrimSpace(creds.Account.Username), "sys") {
		opts["dba privilege"] = "sysdba"
	}
	return go_ora.BuildUrl(creds.Asset.Address, port, svc, creds.Account.Username, creds.Secret, opts)
}

func MySQLDSNMulti(creds assets.TargetCreds, database string) string {
	dsn := MySQLDSN(creds, database)
	if strings.Contains(dsn, "?") {
		return dsn + "&multiStatements=true"
	}
	return dsn + "?multiStatements=true"
}
