package assets

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	_ "github.com/sijms/go-ora/v2"
)

func oracleServiceName(asset Asset) string {
	if s := strings.TrimSpace(asset.DatabaseName); s != "" {
		return s
	}
	return "ORCL"
}

func oraclePort(asset Asset) int {
	if asset.Port > 0 {
		return asset.Port
	}
	return 1521
}

func oracleConnURL(creds TargetCreds, password string) string {
	opts := map[string]string{}
	if strings.EqualFold(strings.TrimSpace(creds.Account.Username), "sys") {
		opts["dba privilege"] = "sysdba"
	}
	return go_ora.BuildUrl(creds.Asset.Address, oraclePort(creds.Asset), oracleServiceName(creds.Asset),
		creds.Account.Username, password, opts)
}

func openOracle(ctx context.Context, connURL string) (*sql.DB, error) {
	db, err := sql.Open("oracle", connURL)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(30 * time.Second)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func verifyOracleCreds(ctx context.Context, creds TargetCreds) error {
	db, err := openOracle(ctx, oracleConnURL(creds, creds.Secret))
	if err != nil {
		return err
	}
	_ = db.Close()
	return nil
}

func (s *Service) rotateOraclePassword(ctx context.Context, creds TargetCreds, newSecret string) error {
	errThin := rotateOraclePasswordThin(ctx, creds, newSecret)
	if errThin == nil {
		return nil
	}
	if err2 := s.rotateOraclePasswordSQLPlus(ctx, creds, newSecret); err2 == nil {
		return nil
	} else {
		return fmt.Errorf("thin: %v; sqlplus: %v", errThin, err2)
	}
}

func rotateOraclePasswordThin(ctx context.Context, creds TargetCreds, newSecret string) error {
	db, err := openOracle(ctx, oracleConnURL(creds, creds.Secret))
	if err != nil {
		return fmt.Errorf("oracle dial: %w", err)
	}
	defer db.Close()

	userIdent := oracleQuoteIdent(creds.Account.Username)
	stmt := fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", userIdent, oracleQuoteLiteral(newSecret))
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("ALTER USER: %w", err)
	}

	vdb, err := openOracle(ctx, oracleConnURL(creds, newSecret))
	if err != nil {
		rollback := fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", userIdent, oracleQuoteLiteral(creds.Secret))
		_, _ = db.ExecContext(ctx, rollback)
		return fmt.Errorf("verify dial failed: %w", err)
	}
	_ = vdb.Close()
	return nil
}

func (s *Service) rotateOraclePasswordSQLPlus(ctx context.Context, creds TargetCreds, newSecret string) error {
	client, err := s.dialManagementSSH(ctx, creds)
	if err != nil {
		return fmt.Errorf("sqlplus path needs SSH :22 on host: %w", err)
	}
	defer client.Close()

	service := oracleServiceName(creds.Asset)
	host := creds.Asset.Address
	port := oraclePort(creds.Asset)
	easyConnect := fmt.Sprintf("%s/%s@//%s:%d/%s",
		shellQuote(creds.Account.Username), shellQuote(creds.Secret), host, port, service)
	alter := fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s",
		oracleQuoteIdent(creds.Account.Username), oracleQuoteLiteral(newSecret))
	script := "sqlplus -S -L " + easyConnect + " <<'EOSQL'\n" +
		"WHENEVER SQLERROR EXIT SQL.SQLCODE\n" +
		alter + "\n" +
		"EXIT;\n" +
		"EOSQL\n"
	_, stderr, err := sshRun(client, "bash -lc "+shellQuote(script))
	if err != nil {
		return fmt.Errorf("sqlplus alter: %v (%s)", err, truncate(stderr, 160))
	}

	verifyEasy := fmt.Sprintf("%s/%s@//%s:%d/%s",
		shellQuote(creds.Account.Username), shellQuote(newSecret), host, port, service)
	verifyScript := "sqlplus -S -L " + verifyEasy + " <<'EOSQL'\nSELECT 1 FROM dual;\nEXIT;\nEOSQL\n"
	_, stderr2, err2 := sshRun(client, "bash -lc "+shellQuote(verifyScript))
	if err2 != nil {
		rollback := fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s",
			oracleQuoteIdent(creds.Account.Username), oracleQuoteLiteral(creds.Secret))
		rbScript := "sqlplus -S -L " + easyConnect + " <<'EOSQL'\n" +
			"WHENEVER SQLERROR EXIT SQL.SQLCODE\n" + rollback + "\nEXIT;\nEOSQL\n"
		_, _, _ = sshRun(client, "bash -lc "+shellQuote(rbScript))
		return fmt.Errorf("sqlplus verify: %v (%s)", err2, truncate(stderr2, 160))
	}
	return nil
}

func oracleQuoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func oracleQuoteLiteral(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
