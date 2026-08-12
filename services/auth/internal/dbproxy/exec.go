package dbproxy

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/assets"
)

type QueryResult struct {
	Columns  []string   `json:"columns"`
	Rows     [][]string `json:"rows"`
	RowCount int        `json:"row_count"`
	Duration int64      `json:"duration_ms"`
	Truncated bool      `json:"truncated,omitempty"`
}

const maxRows = 500
const maxCell = 512

func DialAndQuery(ctx context.Context, creds assets.TargetCreds, statement string) (QueryResult, error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return QueryResult{}, fmt.Errorf("empty statement")
	}
	start := time.Now()
	var res QueryResult
	var err error
	switch creds.Asset.Protocol {
	case "postgres":
		res, err = queryPostgres(ctx, creds, statement)
	case "mysql":
		res, err = queryMySQL(ctx, creds, statement)
	default:
		return QueryResult{}, fmt.Errorf("unsupported db protocol: %s", creds.Asset.Protocol)
	}
	res.Duration = time.Since(start).Milliseconds()
	return res, err
}

func queryPostgres(ctx context.Context, creds assets.TargetCreds, statement string) (QueryResult, error) {
	db := ResolveDatabase("postgres", "", creds.Asset.DatabaseName)
	dsn := PostgresDSN(creds, db)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return QueryResult{}, fmt.Errorf("postgres dial: %w", err)
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, statement)
	if err != nil {
		return QueryResult{}, err
	}
	defer rows.Close()

	fds := rows.FieldDescriptions()
	cols := make([]string, len(fds))
	for i, f := range fds {
		cols[i] = string(f.Name)
	}
	out := QueryResult{Columns: cols, Rows: [][]string{}}
	for rows.Next() {
		if len(out.Rows) >= maxRows {
			out.Truncated = true
			break
		}
		vals, err := rows.Values()
		if err != nil {
			return out, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			row[i] = truncateCell(fmt.Sprint(v))
		}
		out.Rows = append(out.Rows, row)
	}
	out.RowCount = len(out.Rows)
	return out, rows.Err()
}

func queryMySQL(ctx context.Context, creds assets.TargetCreds, statement string) (QueryResult, error) {
	db := ResolveDatabase("mysql", "", creds.Asset.DatabaseName)
	dsn := MySQLDSN(creds, db)
	dbConn, err := sql.Open("mysql", dsn)
	if err != nil {
		return QueryResult{}, err
	}
	defer dbConn.Close()
	dbConn.SetConnMaxLifetime(30 * time.Second)

	rows, err := dbConn.QueryContext(ctx, statement)
	if err != nil {
		return QueryResult{}, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return QueryResult{}, err
	}
	out := QueryResult{Columns: cols, Rows: [][]string{}}
	raw := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	for rows.Next() {
		if len(out.Rows) >= maxRows {
			out.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return out, err
		}
		row := make([]string, len(cols))
		for i, v := range raw {
			if v.Valid {
				row[i] = truncateCell(v.String)
			} else {
				row[i] = "NULL"
			}
		}
		out.Rows = append(out.Rows, row)
	}
	out.RowCount = len(out.Rows)
	return out, rows.Err()
}

func DialTCP(creds assets.TargetCreds) (net.Conn, error) {
	addr := net.JoinHostPort(creds.Asset.Address, strconv.Itoa(creds.Asset.Port))
	return net.DialTimeout("tcp", addr, 15*time.Second)
}

func truncateCell(s string) string {
	if len(s) > maxCell {
		return s[:maxCell] + "…"
	}
	return s
}

func urlUser(s string) string {
	r := strings.NewReplacer(":", "%3A", "/", "%2F", "@", "%40", "?", "%3F", "#", "%23", "%", "%25")
	return r.Replace(s)
}
