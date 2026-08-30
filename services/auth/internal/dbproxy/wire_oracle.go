package dbproxy

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

func (g *WireGateway) authOracle(c net.Conn) (user, pass, db string, err error) {
	pkt, err := readTNS(c)
	if err != nil {
		return "", "", "", err
	}
	if pkt.typ != tnsConnect {
		return "", "", "", fmt.Errorf("expected TNS CONNECT, got 0x%02x", pkt.typ)
	}
	cred := parseOracleConnect(connectDataFromPayload(pkt.payload))
	if err := writeTNS(c, tnsAccept, tnsAcceptPayload()); err != nil {
		return "", "", "", err
	}
	user, pass, db = cred.user, cred.pass, cred.service
	if user != "" && pass != "" {
		return user, pass, db, nil
	}
	deadline := time.Now().Add(12 * time.Second)
	_ = c.SetDeadline(deadline)
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	for i := 0; i < 12; i++ {
		p, rerr := readTNS(c)
		if rerr != nil {
			break
		}
		switch p.typ {
		case tnsMarker:
			_ = writeTNS(c, tnsMarker, []byte{1, 0, 0})
		case tnsData:
			_, body := tnsDataFlags(p.payload)
			switch ttcKind(body) {
			case 0x01:
				_ = writeTNS(c, tnsData, tnsDataPayload([]byte{0x01, 0x06, 'K', 'e', 'e', 'p', 'P', 'A', 'M', 0}))
			case 0x02:
				_ = writeTNS(c, tnsData, tnsDataPayload([]byte{0x02, 0x00}))
			default:
				u, pw := extractOracleAuth(p.payload)
				if user == "" {
					user = u
				}
				if pass == "" {
					pass = pw
				}
				if strings.Contains(strings.ToUpper(string(p.payload)), "AUTH_") {
					_ = writeTNS(c, tnsData, tnsDataPayload([]byte{0x08, 0x01}))
				}
			}
			if user != "" && pass != "" {
				return user, pass, db, nil
			}
		case tnsConnect:
			return "", "", "", fmt.Errorf("unexpected second CONNECT")
		}
	}
	if user == "" {
		return "", "", "", fmt.Errorf("oracle wire: user required (UUID, user+ASSET, or CONNECT_DATA KEEPPAM_USER)")
	}
	return user, pass, db, nil
}

func (g *WireGateway) serveOracle(ctx context.Context, client net.Conn, creds assets.TargetCreds, sessionID, userID uuid.UUID, rec *Recorder) {
	dsn := OracleDSN(creds, ResolveDatabase("oracle", "", creds.Asset.DatabaseName))
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		_ = writeTNS(client, tnsData, tnsDataPayload([]byte(err.Error())))
		return
	}
	defer db.Close()
	db.SetConnMaxLifetime(30 * time.Second)
	if err := db.PingContext(ctx); err != nil {
		_ = writeTNS(client, tnsData, tnsDataPayload([]byte(err.Error())))
		return
	}
	guard := g.loadGuard(ctx, sessionID)
	for {
		pkt, err := readTNS(client)
		if err != nil {
			return
		}
		switch pkt.typ {
		case tnsMarker, tnsNull:
			if pkt.typ == tnsMarker {
				_ = writeTNS(client, tnsMarker, []byte{1, 0, 0})
			}
		case tnsAbort:
			return
		case tnsData:
			_, body := tnsDataFlags(pkt.payload)
			if ttcKind(body) == 0x01 {
				_ = writeTNS(client, tnsData, tnsDataPayload([]byte{0x01, 0x06}))
				continue
			}
			if ttcKind(body) == 0x02 {
				_ = writeTNS(client, tnsData, tnsDataPayload([]byte{0x02, 0x00}))
				continue
			}
			stmt := extractSQL(pkt.payload)
			if stmt == "" {
				continue
			}
			if guard != nil && guard.Allow != nil {
				if ok, reason := guard.Allow(stmt); !ok {
					g.denySQL(ctx, sessionID, userID, stmt, reason)
					_ = writeTNS(client, tnsData, tnsDataPayload([]byte("ORA-01031: "+reason)))
					continue
				}
			}
			g.execAndRecord(ctx, sessionID, userID, stmt, rec, func() error {
				return writeOracleQueryResult(ctx, client, db, stmt, guard)
			})
		default:
			return
		}
	}
}

func writeOracleQueryResult(ctx context.Context, client net.Conn, db *sql.DB, stmt string, guard *SQLGuard) error {
	rows, err := db.QueryContext(ctx, stmt)
	if err != nil {
		_ = writeTNS(client, tnsData, tnsDataPayload([]byte(err.Error())))
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		_ = writeTNS(client, tnsData, tnsDataPayload([]byte(err.Error())))
		return err
	}
	raw := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	limit := guard.rowLimit()
	var buffered [][]string
	truncated := false
	for rows.Next() {
		if len(buffered) >= limit {
			truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			break
		}
		row := make([]string, len(cols))
		for i, v := range raw {
			if v.Valid {
				row[i] = truncateCell(v.String)
			}
		}
		buffered = append(buffered, row)
	}
	if truncated && guard.denyOverflow() {
		msg := fmt.Sprintf("%s (%d)", ErrDLPRowLimit.Error(), limit)
		_ = writeTNS(client, tnsData, tnsDataPayload([]byte(msg)))
		return fmt.Errorf("%w (%d)", ErrDLPRowLimit, limit)
	}
	var ferr error
	buffered, ferr = guard.applyRows(cols, buffered)
	if ferr != nil {
		_ = writeTNS(client, tnsData, tnsDataPayload([]byte(ferr.Error())))
		return ferr
	}
	_ = rows.Err()
	return writeTNS(client, tnsData, tnsDataPayload([]byte(formatOracleTable(cols, buffered))))
}

func formatOracleTable(cols []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString(strings.Join(cols, "\t"))
	b.WriteByte('\n')
	for _, row := range rows {
		b.WriteString(strings.Join(row, "\t"))
		b.WriteByte('\n')
	}
	b.WriteString(fmt.Sprintf("%d rows\n", len(rows)))
	return b.String()
}

func sendOracleFail(c net.Conn, msg string) error {
	return writeTNS(c, tnsRefuse, tnsRefusePayload(msg))
}

func sendOracleOK(c net.Conn) error {
	return writeTNS(c, tnsData, tnsDataPayload([]byte{0x08, 0x01}))
}
