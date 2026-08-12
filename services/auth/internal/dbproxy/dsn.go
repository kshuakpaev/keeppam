package dbproxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/keeppam/auth/internal/assets"
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

func MySQLDSNMulti(creds assets.TargetCreds, database string) string {
	dsn := MySQLDSN(creds, database)
	if strings.Contains(dsn, "?") {
		return dsn + "&multiStatements=true"
	}
	return dsn + "?multiStatements=true"
}
