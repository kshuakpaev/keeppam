package dbproxy

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
)

func (g *WireGateway) authMSSQL(c net.Conn) (uuid.UUID, string, string, error) {
	for {
		typ, payload, err := readTDSMessage(c)
		if err != nil {
			return uuid.Nil, "", "", err
		}
		switch typ {
		case tdsPrelogin:
			if err := writePreloginResponse(c); err != nil {
				return uuid.Nil, "", "", err
			}
		case tdsLogin7:
			user, pass, db, err := parseLogin7(payload)
			if err != nil {
				return uuid.Nil, "", "", err
			}
			id, err := uuid.Parse(user)
			if err != nil {
				return uuid.Nil, "", "", fmt.Errorf("user must be session uuid")
			}
			return id, pass, db, nil
		default:
			return uuid.Nil, "", "", fmt.Errorf("expected PRELOGIN or LOGIN7, got 0x%02x", typ)
		}
	}
}

func (g *WireGateway) serveMSSQL(ctx context.Context, client net.Conn, creds assets.TargetCreds, sessionID, userID uuid.UUID, rec *Recorder) {
	dsn := MSSQLDSN(creds, ResolveDatabase("mssql", "", creds.Asset.DatabaseName))
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		_ = writeTDSMessage(client, tdsTabular, tdsError(err.Error()))
		return
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		_ = writeTDSMessage(client, tdsTabular, tdsError(err.Error()))
		return
	}
	guard := g.loadGuard(ctx, sessionID)
	for {
		typ, payload, err := readTDSMessage(client)
		if err != nil {
			return
		}
		switch typ {
		case tdsSQLBatch:
			stmt := sqlBatchText(payload)
			if stmt == "" {
				_ = writeTDSMessage(client, tdsTabular, tdsDONE(0, 0))
				continue
			}
			if guard != nil && guard.Allow != nil {
				if ok, reason := guard.Allow(stmt); !ok {
					g.denySQL(ctx, sessionID, userID, stmt, reason)
					_ = writeTDSMessage(client, tdsTabular, tdsError(reason))
					continue
				}
			}
			g.execAndRecord(ctx, sessionID, userID, stmt, rec, func() error {
				return writeMSSQLQueryResult(ctx, client, db, stmt, guard)
			})
		case tdsAttention:
			_ = writeTDSMessage(client, tdsTabular, tdsDONE(0x20, 0)) // DONE_ATTN
		case tdsRPC, tdsBulk, tdsTM:
			_ = writeTDSMessage(client, tdsTabular, tdsError("command not supported in KeepPAM MSSQL wire; use SQL batch"))
		default:
			if typ == tdsLogin7 || typ == tdsPrelogin {
				return
			}
			_ = writeTDSMessage(client, tdsTabular, tdsError("unknown TDS packet"))
		}
	}
}

func writeMSSQLQueryResult(ctx context.Context, client net.Conn, db *sql.DB, stmt string, guard *SQLGuard) error {
	rows, err := db.QueryContext(ctx, stmt)
	if err != nil {
		_ = writeTDSMessage(client, tdsTabular, tdsError(err.Error()))
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		_ = writeTDSMessage(client, tdsTabular, tdsError(err.Error()))
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
		_ = writeTDSMessage(client, tdsTabular, tdsError(msg))
		return fmt.Errorf("%w (%d)", ErrDLPRowLimit, limit)
	}
	var ferr error
	buffered, ferr = guard.applyRows(cols, buffered)
	if ferr != nil {
		_ = writeTDSMessage(client, tdsTabular, tdsError(ferr.Error()))
		return ferr
	}
	_ = rows.Err()
	return writeTDSMessage(client, tdsTabular, tdsResultSet(cols, buffered))
}

func sendMSSQLFail(c net.Conn, msg string) error {
	return writeTDSMessage(c, tdsTabular, tdsError(msg))
}

func sendMSSQLOK(c net.Conn, database string) error {
	return writeTDSMessage(c, tdsTabular, tdsLoginAck(database))
}
