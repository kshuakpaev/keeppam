package dbproxy

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sessionsvc"
)

const wireTokenPrefix = "keeppam:dbwire:"

type WireGateway struct {
	addr      string
	protocol  string
	rdb       *redis.Client
	assets    *assets.Service
	sessions  *sessionsvc.Service
	audit     *audit.Service
	live      *sessionsvc.LiveHub
	ensureEph EnsureEphemeral
	sqlGuard  ResolveSQLGuard
	pamStart  PamStart
}

// EnsureEphemeral creates a temporary DB role and returns dial credentials.
type EnsureEphemeral func(ctx context.Context, sessionID uuid.UUID, vault assets.TargetCreds, privilege string) (creds assets.TargetCreds, roleName string, err error)

// SQLGuard enforces table JEA, DLP export/row limits, and column masking.
type SQLGuard struct {
	Allow      func(stmt string) (ok bool, reason string)
	Mask       func(cols []string, rows [][]string) ([]string, [][]string)
	FilterRows func(cols []string, rows [][]string) ([][]string, error)
	MaxRows    int
	DLPDeny    bool
}

func (g *SQLGuard) applyRows(cols []string, rows [][]string) ([][]string, error) {
	if g != nil && g.Mask != nil {
		_, rows = g.Mask(cols, rows)
	}
	if g != nil && g.FilterRows != nil {
		return g.FilterRows(cols, rows)
	}
	return rows, nil
}

func (g *SQLGuard) rowLimit() int {
	if g != nil && g.MaxRows > 0 {
		return effectiveMaxRows(g.MaxRows)
	}
	return defaultMaxRows
}

func (g *SQLGuard) denyOverflow() bool {
	return g != nil && g.DLPDeny
}

type ResolveSQLGuard func(ctx context.Context, sessionID uuid.UUID) (*SQLGuard, error)

// PamStart creates a session from PAM username/password (native client, no portal).
type PamStart func(ctx context.Context, protocol, username, password, hint, ip string) (sessionID uuid.UUID, token string, err error)

func (g *WireGateway) SetPamStart(fn PamStart) {
	if g != nil {
		g.pamStart = fn
	}
}

func NewWireGateway(addr, protocol string, rdb *redis.Client, assetsSvc *assets.Service, sess *sessionsvc.Service, aud *audit.Service, live *sessionsvc.LiveHub, ensure EnsureEphemeral, sqlGuard ResolveSQLGuard) *WireGateway {
	return &WireGateway{addr: addr, protocol: protocol, rdb: rdb, assets: assetsSvc, sessions: sess, audit: aud, live: live, ensureEph: ensure, sqlGuard: sqlGuard}
}

func IssueWireToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, ttl time.Duration) (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(randReader(), b); err != nil {
		return "", err
	}
	tok := fmt.Sprintf("%x", b)
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return tok, rdb.Set(ctx, wireTokenPrefix+sessionID.String(), tok, ttl).Err()
}

func ClearWireToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID) {
	_ = rdb.Del(ctx, wireTokenPrefix+sessionID.String()).Err()
}

// CheckWireToken returns true if token matches the Redis value for the session.
func CheckWireToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, token string) bool {
	if rdb == nil || token == "" {
		return false
	}
	want, err := rdb.Get(ctx, wireTokenPrefix+sessionID.String()).Result()
	if err != nil {
		return false
	}
	a, b := []byte(want), []byte(token)
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (g *WireGateway) ListenAndServe(ctx context.Context) error {
	if g.addr == "" || g.addr == "off" {
		<-ctx.Done()
		return nil
	}
	ln, err := net.Listen("tcp", g.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	slog.Info("db wire gateway", "addr", g.addr, "protocol", g.protocol)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go g.handleConn(c)
	}
}

func (g *WireGateway) handleConn(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(60 * time.Second))
	ctx := context.Background()

	user, token, clientDB, err := g.clientAuth(client)
	if err != nil {
		slog.Info("db wire auth failed", "protocol", g.protocol, "err", err)
		return
	}
	ip := ""
	if ta, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		ip = ta.IP.String()
	}
	sessionID, parseErr := uuid.Parse(user)
	tokenOK := false
	if parseErr == nil {
		want, werr := g.rdb.Get(ctx, wireTokenPrefix+sessionID.String()).Result()
		tokenOK = werr == nil && want != "" && want == token
	}
	if !tokenOK && g.pamStart != nil {
		sid, tok, perr := g.pamStart(ctx, g.protocol, user, token, clientDB, ip)
		if perr != nil {
			_ = g.sendAuthFail(client, perr.Error())
			return
		}
		sessionID, token = sid, tok
		tokenOK = true
	}
	if !tokenOK {
		_ = g.sendAuthFail(client, "invalid wire token")
		return
	}
	row, err := g.sessions.Get(ctx, sessionID)
	if err != nil || (row.Status != "pending" && row.Status != "active") {
		_ = g.sendAuthFail(client, "session not active")
		return
	}
	if row.IsWaitingSupervisor() {
		_ = g.sendAuthFail(client, "waiting for supervisor")
		return
	}
	if row.Protocol != g.protocol {
		_ = g.sendAuthFail(client, "protocol mismatch")
		return
	}
	creds, err := g.assets.GetTargetCreds(ctx, row.AssetID, row.AccountID)
	if err != nil {
		_ = g.sendAuthFail(client, "creds error")
		return
	}
	wantDB := ResolveDatabase(row.Protocol, row.DatabaseName, creds.Asset.DatabaseName)
	creds.Asset.DatabaseName = wantDB
	if clientDB != "" && !strings.EqualFold(clientDB, wantDB) {
		_ = g.sendAuthFail(client, fmt.Sprintf("database mismatch: session is %q, client asked %q", wantDB, clientDB))
		return
	}
	ephRole := ""
	if g.ensureEph != nil && UsesEphemeralDBRole(g.protocol) {
		ephCreds, roleName, eerr := g.ensureEph(ctx, sessionID, creds, row.DBPrivilege)
		if eerr != nil {
			_ = g.sendAuthFail(client, "ephemeral role: "+eerr.Error())
			return
		}
		creds = ephCreds
		creds.Asset.DatabaseName = wantDB
		ephRole = roleName
	}

	if err := g.sendAuthOK(client, wantDB); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	_ = g.sessions.MarkActive(ctx, sessionID)
	_ = g.audit.Record(ctx, &row.UserID, "session.started", "session", sessionID.String(), client.RemoteAddr().String(), "dbwire", map[string]any{
		"protocol": g.protocol, "via": "wire", "ephemeral_role": ephRole,
	})
	rec, _ := NewRecorder(row.RecordingPath)
	defer rec.Close()

	unregister := g.live.Register(sessionID, func() { _ = client.Close() })
	defer unregister()
	hbStop := make(chan struct{})
	defer close(hbStop)
	go sessionsvc.Heartbeat(ctx, g.sessions, sessionID, 30*time.Second, hbStop)

	switch g.protocol {
	case "postgres":
		g.servePostgres(ctx, client, creds, sessionID, row.UserID, rec)
	case "mysql":
		g.serveMySQL(ctx, client, creds, sessionID, row.UserID, rec)
	case "mssql":
		g.serveMSSQL(ctx, client, creds, sessionID, row.UserID, rec)
	case "oracle":
		g.serveOracle(ctx, client, creds, sessionID, row.UserID, rec)
	}
	_ = g.sessions.MarkEnded(ctx, sessionID, "")
	ClearWireToken(ctx, g.rdb, sessionID)
}

func (g *WireGateway) loadGuard(ctx context.Context, sessionID uuid.UUID) *SQLGuard {
	fallback := &SQLGuard{
		Allow:   func(stmt string) (bool, string) { return policy.AllowSQL(policy.SQLPack{}, false, stmt) },
		MaxRows: defaultMaxRows,
	}
	if g.sqlGuard == nil {
		return fallback
	}
	g2, err := g.sqlGuard(ctx, sessionID)
	if err != nil || g2 == nil {
		return fallback
	}
	if g2.Allow == nil {
		g2.Allow = fallback.Allow
	}
	return g2
}

func (g *WireGateway) denySQL(ctx context.Context, sessionID, userID uuid.UUID, stmt, reason string) {
	payload := map[string]any{"statement": truncateStmt(stmt), "reason": reason, "via": "wire", "denied": true}
	_ = g.sessions.AddEvent(ctx, sessionID, "sql_denied", payload)
	g.live.FanoutSQL(ctx, sessionID, payload)
	_ = g.audit.Record(ctx, &userID, "session.sql.denied", "session", sessionID.String(), "", "dbwire", map[string]any{
		"statement": truncateStmt(stmt), "reason": reason,
	})
}

func (g *WireGateway) servePostgres(ctx context.Context, client net.Conn, creds assets.TargetCreds, sessionID, userID uuid.UUID, rec *Recorder) {
	dsn := PostgresDSN(creds, ResolveDatabase("postgres", "", creds.Asset.DatabaseName))
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		_ = writePGMsg(client, 'E', pgErrorBody(err.Error()))
		return
	}
	defer conn.Close(ctx)
	guard := g.loadGuard(ctx, sessionID)

	for {
		msg, err := readPGMsg(client)
		if err != nil {
			return
		}
		switch msg.tag {
		case 'Q':
			stmt := strings.TrimRight(string(msg.body), "\x00")
			if guard != nil && guard.Allow != nil {
				if ok, reason := guard.Allow(stmt); !ok {
					g.denySQL(ctx, sessionID, userID, stmt, reason)
					_ = writePGMsg(client, 'E', pgErrorBody(reason))
					_ = writePGMsg(client, 'Z', []byte{'I'})
					continue
				}
			}
			g.execAndRecord(ctx, sessionID, userID, stmt, rec, func() error {
				return writePGQueryResult(ctx, client, conn, stmt, guard)
			})
		case 'X':
			return
		case 'P', 'B', 'D', 'E', 'S', 'H', 'C':
			_ = writePGMsg(client, 'E', pgErrorBody("extended protocol not supported; use simple Query"))
			_ = writePGMsg(client, 'Z', []byte{'I'})
		default:
			_ = writePGMsg(client, 'Z', []byte{'I'})
		}
	}
}

func (g *WireGateway) serveMySQL(ctx context.Context, client net.Conn, creds assets.TargetCreds, sessionID, userID uuid.UUID, rec *Recorder) {
	dsn := MySQLDSN(creds, ResolveDatabase("mysql", "", creds.Asset.DatabaseName))
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		_ = writeMySQLPacket(client, 1, mysqlErr(err.Error()))
		return
	}
	defer db.Close()
	seq := byte(0)
	guard := g.loadGuard(ctx, sessionID)
	for {
		pkt, s, err := readMySQLPacket(client)
		if err != nil {
			return
		}
		seq = s + 1
		if len(pkt) == 0 {
			continue
		}
		switch pkt[0] {
		case 0x01: // COM_QUIT
			return
		case 0x03: // COM_QUERY
			stmt := string(pkt[1:])
			if guard != nil && guard.Allow != nil {
				if ok, reason := guard.Allow(stmt); !ok {
					g.denySQL(ctx, sessionID, userID, stmt, reason)
					_ = writeMySQLPacket(client, seq, mysqlErr(reason))
					seq++
					continue
				}
			}
			g.execAndRecord(ctx, sessionID, userID, stmt, rec, func() error {
				return writeMySQLQueryResult(ctx, client, db, stmt, &seq, guard)
			})
		default:
			_ = writeMySQLPacket(client, seq, mysqlErr("command not supported in KeepPAM wire MVP"))
			seq++
		}
	}
}

func (g *WireGateway) execAndRecord(ctx context.Context, sessionID, userID uuid.UUID, stmt string, rec *Recorder, run func() error) {
	start := time.Now()
	err := run()
	ms := time.Since(start).Milliseconds()
	if errors.Is(err, ErrDLPRowLimit) || errors.Is(err, ErrPIIContent) {
		g.denySQL(ctx, sessionID, userID, stmt, err.Error())
		if errors.Is(err, ErrPIIContent) {
			_ = g.sessions.AddEvent(ctx, sessionID, "dlp", map[string]any{
				"reason": err.Error(), "via": "wire",
			})
			_ = g.audit.Record(ctx, &userID, "session.dlp.denied", "session", sessionID.String(), "", "dbwire", map[string]any{
				"reason": err.Error(),
			})
		}
		rec.Record(stmt, ms, 0, err.Error())
		return
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	rec.Record(stmt, ms, 0, errMsg)
	sqlEv := map[string]any{"statement": truncateStmt(stmt), "via": "wire", "error": errMsg, "duration_ms": ms}
	_ = g.sessions.AddEvent(ctx, sessionID, "sql", sqlEv)
	g.live.FanoutSQL(ctx, sessionID, sqlEv)
	_ = g.audit.Record(ctx, &userID, "session.sql", "session", sessionID.String(), "", "dbwire", map[string]any{
		"statement": truncateStmt(stmt), "via": "wire", "error": errMsg,
	})
}

func writePGQueryResult(ctx context.Context, client net.Conn, conn *pgx.Conn, stmt string, guard *SQLGuard) error {
	rows, err := conn.Query(ctx, stmt)
	if err != nil {
		_ = writePGMsg(client, 'E', pgErrorBody(err.Error()))
		return writePGMsg(client, 'Z', []byte{'I'})
	}
	defer rows.Close()
	fds := rows.FieldDescriptions()
	colNames := make([]string, len(fds))
	for i, f := range fds {
		colNames[i] = string(f.Name)
	}
	limit := guard.rowLimit()
	var buffered [][]string
	truncated := false
	for rows.Next() {
		if len(buffered) >= limit {
			truncated = true
			break
		}
		vals, err := rows.Values()
		if err != nil {
			break
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			if v == nil {
				row[i] = ""
			} else {
				row[i] = fmt.Sprint(v)
			}
		}
		buffered = append(buffered, row)
	}
	if truncated && guard.denyOverflow() {
		msg := fmt.Sprintf("%s (%d)", ErrDLPRowLimit.Error(), limit)
		_ = writePGMsg(client, 'E', pgErrorBody(msg))
		_ = writePGMsg(client, 'Z', []byte{'I'})
		return fmt.Errorf("%w (%d)", ErrDLPRowLimit, limit)
	}
	var ferr error
	buffered, ferr = guard.applyRows(colNames, buffered)
	if ferr != nil {
		_ = writePGMsg(client, 'E', pgErrorBody(ferr.Error()))
		_ = writePGMsg(client, 'Z', []byte{'I'})
		return ferr
	}
	rd := binary.BigEndian.AppendUint16(nil, uint16(len(fds)))
	for _, f := range fds {
		rd = append(rd, []byte(f.Name)...)
		rd = append(rd, 0)
		tmp := make([]byte, 18)
		binary.BigEndian.PutUint32(tmp[6:10], uint32(f.DataTypeOID))
		binary.BigEndian.PutUint16(tmp[10:12], 0xffff)
		rd = append(rd, tmp...)
	}
	if err := writePGMsg(client, 'T', rd); err != nil {
		return err
	}
	for _, cells := range buffered {
		row := binary.BigEndian.AppendUint16(nil, uint16(len(cells)))
		for i, s := range cells {
			_ = i
			b := []byte(s)
			row = binary.BigEndian.AppendUint32(row, uint32(len(b)))
			row = append(row, b...)
		}
		if err := writePGMsg(client, 'D', row); err != nil {
			return err
		}
	}
	tag := fmt.Sprintf("SELECT %d", len(buffered))
	if err := writePGMsg(client, 'C', append([]byte(tag), 0)); err != nil {
		return err
	}
	return writePGMsg(client, 'Z', []byte{'I'})
}

func writeMySQLQueryResult(ctx context.Context, client net.Conn, db *sql.DB, stmt string, seq *byte, guard *SQLGuard) error {
	rows, err := db.QueryContext(ctx, stmt)
	if err != nil {
		_ = writeMySQLPacket(client, *seq, mysqlErr(err.Error()))
		*seq++
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	raw := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	limit := guard.rowLimit()
	var buffered [][]string
	var nulls [][]bool
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
		nuls := make([]bool, len(cols))
		for i, v := range raw {
			if v.Valid {
				row[i] = truncateCell(v.String)
			} else {
				nuls[i] = true
			}
		}
		buffered = append(buffered, row)
		nulls = append(nulls, nuls)
	}
	if truncated && guard.denyOverflow() {
		msg := fmt.Sprintf("%s (%d)", ErrDLPRowLimit.Error(), limit)
		_ = writeMySQLPacket(client, *seq, mysqlErr(msg))
		*seq++
		return fmt.Errorf("%w (%d)", ErrDLPRowLimit, limit)
	}
	var ferr error
	buffered, ferr = guard.applyRows(cols, buffered)
	if ferr != nil {
		_ = writeMySQLPacket(client, *seq, mysqlErr(ferr.Error()))
		*seq++
		return ferr
	}
	_ = writeMySQLPacket(client, *seq, []byte{byte(len(cols))})
	*seq++
	for _, c := range cols {
		def := mysqlColumnDef(c)
		_ = writeMySQLPacket(client, *seq, def)
		*seq++
	}
	_ = writeMySQLPacket(client, *seq, []byte{0xfe, 0, 0, 2, 0})
	*seq++
	for ri, cells := range buffered {
		row := []byte{}
		for i, s := range cells {
			if ri < len(nulls) && nulls[ri][i] && s == "" {
				row = append(row, 0xfb)
				continue
			}
			row = appendLenEnc(row, []byte(s))
		}
		_ = writeMySQLPacket(client, *seq, row)
		*seq++
	}
	_ = writeMySQLPacket(client, *seq, []byte{0xfe, 0, 0, 2, 0})
	*seq++
	return nil
}

func (g *WireGateway) clientAuth(c net.Conn) (user, token, clientDB string, err error) {
	switch g.protocol {
	case "postgres":
		return g.authPostgres(c)
	case "mssql":
		return g.authMSSQL(c)
	case "oracle":
		return g.authOracle(c)
	default:
		u, tok, err := g.authMySQL(c)
		return u, tok, "", err
	}
}

func (g *WireGateway) sendAuthFail(c net.Conn, msg string) error {
	switch g.protocol {
	case "postgres":
		return writePGMsg(c, 'E', pgErrorBody(msg))
	case "mssql":
		return sendMSSQLFail(c, msg)
	case "oracle":
		return sendOracleFail(c, msg)
	default:
		return writeMySQLPacket(c, 2, mysqlErr(msg))
	}
}

func (g *WireGateway) sendAuthOK(c net.Conn, database string) error {
	switch g.protocol {
	case "postgres":
		if err := writePGMsg(c, 'R', []byte{0, 0, 0, 0}); err != nil {
			return err
		}
		_ = writePGMsg(c, 'S', append([]byte("server_version\x00"), []byte("14.0-keeppam\x00")...))
		return writePGMsg(c, 'Z', []byte{'I'})
	case "mssql":
		return sendMSSQLOK(c, database)
	case "oracle":
		return sendOracleOK(c)
	default:
		return writeMySQLPacket(c, 2, []byte{0, 0, 0, 2, 0, 0, 0})
	}
}

func (g *WireGateway) authPostgres(c net.Conn) (user, pass, db string, err error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", "", "", err
	}
	length := int(binary.BigEndian.Uint32(hdr[0:4]))
	if length < 8 || length > 10000 {
		return "", "", "", fmt.Errorf("bad startup length")
	}
	rest := make([]byte, length-8)
	if _, err := io.ReadFull(c, rest); err != nil {
		return "", "", "", err
	}
	if binary.BigEndian.Uint32(hdr[4:8]) == 80877103 {
		_, _ = c.Write([]byte{'N'})
		return g.authPostgres(c)
	}
	params := parsePGStartup(rest)
	user = strings.TrimSpace(params["user"])
	if user == "" {
		return "", "", "", fmt.Errorf("user required")
	}
	if err := writePGMsg(c, 'R', []byte{0, 0, 0, 3}); err != nil {
		return "", "", "", err
	}
	msg, err := readPGMsg(c)
	if err != nil {
		return "", "", "", err
	}
	if msg.tag != 'p' {
		return "", "", "", fmt.Errorf("expected password")
	}
	return user, strings.TrimRight(string(msg.body), "\x00"), strings.TrimSpace(params["database"]), nil
}

func (g *WireGateway) authMySQL(c net.Conn) (user, pass string, err error) {
	salt := make([]byte, 20)
	_, _ = io.ReadFull(randReader(), salt)
	payload := []byte{10}
	payload = append(payload, "5.7.0-keeppam\x00"...)
	payload = append(payload, 1, 0, 0, 0)
	payload = append(payload, salt[:8]...)
	payload = append(payload, 0)
	payload = append(payload, 0xff, 0xf7)
	payload = append(payload, 33)
	payload = append(payload, 0x02, 0x00)
	payload = append(payload, 0xff, 0x81)
	payload = append(payload, 21)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, salt[8:]...)
	payload = append(payload, 0)
	payload = append(payload, "mysql_clear_password\x00"...)
	if err := writeMySQLPacket(c, 0, payload); err != nil {
		return "", "", err
	}
	pkt, _, err := readMySQLPacket(c)
	if err != nil {
		return "", "", err
	}
	if len(pkt) < 32 {
		return "", "", fmt.Errorf("short handshake response")
	}
	user, i := readNull(pkt, 32)
	pass = ""
	if i < len(pkt) {
		if pkt[i] != 0 && int(pkt[i]) < 250 && i+1+int(pkt[i]) <= len(pkt) {
			n := int(pkt[i])
			pass = string(pkt[i+1 : i+1+n])
		} else {
			pass, _ = readNull(pkt, i)
		}
	}
	return user, strings.TrimRight(pass, "\x00"), nil
}

func pgErrorBody(msg string) []byte {
	body := []byte{'S'}
	body = append(body, "ERROR\x00"...)
	body = append(body, 'C')
	body = append(body, "XX000\x00"...)
	body = append(body, 'M')
	body = append(body, msg...)
	body = append(body, 0, 0)
	return body
}

func mysqlErr(msg string) []byte {
	p := []byte{0xff, 0x15, 0x04, '#'}
	p = append(p, "HY000"...)
	p = append(p, msg...)
	return p
}

func mysqlColumnDef(name string) []byte {
	// simplified column definition packet
	p := appendLenEnc(nil, []byte("def"))
	p = appendLenEnc(p, []byte(""))
	p = appendLenEnc(p, []byte(""))
	p = appendLenEnc(p, []byte(""))
	p = appendLenEnc(p, []byte(name))
	p = appendLenEnc(p, []byte(name))
	p = append(p, 0x0c)        // length of fixed fields
	p = append(p, 0x21, 0x00)  // charset
	p = append(p, 0, 0, 0, 64) // column length
	p = append(p, 0xfd)        // type varchar
	p = append(p, 0, 0)        // flags
	p = append(p, 0)           // decimals
	p = append(p, 0, 0)        // filler
	return p
}

func appendLenEnc(b, v []byte) []byte {
	n := len(v)
	if n < 251 {
		b = append(b, byte(n))
	} else {
		b = append(b, 0xfc, byte(n), byte(n>>8))
	}
	return append(b, v...)
}
