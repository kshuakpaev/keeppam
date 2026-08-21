package policy

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/store"
)

type SQLPack struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Mode            string    `json:"mode"` // allowlist|denylist
	Statements      []string  `json:"statements"`
	Tables          []string  `json:"tables"`
	MaskColumns     []string  `json:"mask_columns"`
	MaskReplacement string    `json:"mask_replacement"`
	MaxRows         int       `json:"max_rows"`
	DLPAction       string    `json:"dlp_action"` // truncate|deny
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type SQLPackInput struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Mode            string   `json:"mode"`
	Statements      []string `json:"statements"`
	Tables          []string `json:"tables"`
	MaskColumns     []string `json:"mask_columns"`
	MaskReplacement string   `json:"mask_replacement"`
	MaxRows         int      `json:"max_rows"`
	DLPAction       string   `json:"dlp_action"`
}

func (s *Service) ListSQLPacks(ctx context.Context) ([]SQLPack, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, mode, statements, tables, mask_columns, mask_replacement,
			COALESCE(max_rows,500), COALESCE(dlp_action,'truncate'), created_at, updated_at
		FROM sql_policy_packs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SQLPack
	for rows.Next() {
		p, err := scanSQLPack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []SQLPack{}
	}
	return out, rows.Err()
}

func (s *Service) GetSQLPack(ctx context.Context, id uuid.UUID) (SQLPack, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, mode, statements, tables, mask_columns, mask_replacement,
			COALESCE(max_rows,500), COALESCE(dlp_action,'truncate'), created_at, updated_at
		FROM sql_policy_packs WHERE id=$1`, id)
	return scanSQLPack(row)
}

func (s *Service) CreateSQLPack(ctx context.Context, actorID uuid.UUID, in SQLPackInput, ip, ua string) (SQLPack, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return SQLPack{}, fmt.Errorf("name required")
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "allowlist"
	}
	if mode != "allowlist" && mode != "denylist" {
		return SQLPack{}, fmt.Errorf("invalid mode")
	}
	stmts := normalizeSQLTokens(in.Statements)
	tables := normalizePatterns(in.Tables)
	masks := normalizePatterns(in.MaskColumns)
	repl := strings.TrimSpace(in.MaskReplacement)
	if repl == "" {
		repl = "***"
	}
	maxRows, dlpAction := normalizeSQLDLP(in.MaxRows, in.DLPAction)
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO sql_policy_packs
			(id, name, description, mode, statements, tables, mask_columns, mask_replacement, max_rows, dlp_action, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())`,
		id, name, strings.TrimSpace(in.Description), mode, stmts, tables, masks, repl, maxRows, dlpAction)
	if err != nil {
		return SQLPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.sql_pack.created", "sql_policy_pack", id.String(), ip, ua, map[string]any{
		"name": name, "mode": mode, "tables": tables, "statements": stmts,
	})
	return s.GetSQLPack(ctx, id)
}

func (s *Service) UpdateSQLPack(ctx context.Context, actorID, id uuid.UUID, in SQLPackInput, ip, ua string) (SQLPack, error) {
	cur, err := s.GetSQLPack(ctx, id)
	if err != nil {
		return SQLPack{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = cur.Name
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = cur.Mode
	}
	if mode != "allowlist" && mode != "denylist" {
		return SQLPack{}, fmt.Errorf("invalid mode")
	}
	stmts := normalizeSQLTokens(in.Statements)
	if in.Statements == nil {
		stmts = cur.Statements
	}
	tables := normalizePatterns(in.Tables)
	if in.Tables == nil {
		tables = cur.Tables
	}
	masks := normalizePatterns(in.MaskColumns)
	if in.MaskColumns == nil {
		masks = cur.MaskColumns
	}
	repl := strings.TrimSpace(in.MaskReplacement)
	if repl == "" {
		repl = cur.MaskReplacement
	}
	maxRows, dlpAction := normalizeSQLDLP(in.MaxRows, in.DLPAction)
	if in.MaxRows == 0 {
		maxRows = cur.MaxRows
		if maxRows <= 0 {
			maxRows = 500
		}
	}
	if strings.TrimSpace(in.DLPAction) == "" {
		dlpAction = cur.DLPAction
		if dlpAction == "" {
			dlpAction = "truncate"
		}
	}
	desc := in.Description
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE sql_policy_packs SET name=$2, description=$3, mode=$4, statements=$5, tables=$6,
			mask_columns=$7, mask_replacement=$8, max_rows=$9, dlp_action=$10, updated_at=NOW()
		WHERE id=$1`, id, name, desc, mode, stmts, tables, masks, repl, maxRows, dlpAction)
	if err != nil {
		return SQLPack{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "jea.sql_pack.updated", "sql_policy_pack", id.String(), ip, ua, map[string]any{
		"name": name, "mode": mode,
	})
	return s.GetSQLPack(ctx, id)
}

func (s *Service) DeleteSQLPack(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM sql_policy_packs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return s.aud.Record(ctx, &actorID, "jea.sql_pack.deleted", "sql_policy_pack", id.String(), ip, ua, nil)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSQLPack(row scannable) (SQLPack, error) {
	var p SQLPack
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Mode, &p.Statements, &p.Tables,
		&p.MaskColumns, &p.MaskReplacement, &p.MaxRows, &p.DLPAction, &p.CreatedAt, &p.UpdatedAt)
	if p.Statements == nil {
		p.Statements = []string{}
	}
	if p.Tables == nil {
		p.Tables = []string{}
	}
	if p.MaskColumns == nil {
		p.MaskColumns = []string{}
	}
	if p.MaskReplacement == "" {
		p.MaskReplacement = "***"
	}
	if p.MaxRows <= 0 {
		p.MaxRows = 500
	}
	if p.DLPAction == "" {
		p.DLPAction = "truncate"
	}
	return p, err
}

func normalizeSQLDLP(maxRows int, action string) (int, string) {
	if maxRows <= 0 {
		maxRows = 500
	}
	if maxRows > 100000 {
		maxRows = 100000
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "deny" {
		action = "truncate"
	}
	return maxRows, action
}

func normalizeSQLTokens(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range in {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if out == nil {
		return []string{}
	}
	return out
}

var (
	reSQLComments = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\n]*`)
	reSQLFrom     = regexp.MustCompile(`(?i)\b(?:from|join|update|into|table|truncate)\s+([a-zA-Z0-9_."]+)`)
)

// ClassifySQL returns verb category and referenced table names (best-effort).
func ClassifySQL(statement string) (verb string, tables []string) {
	s := strings.TrimSpace(reSQLComments.ReplaceAllString(statement, " "))
	if s == "" {
		return "", nil
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", nil
	}
	first := strings.ToUpper(strings.TrimSuffix(fields[0], ";"))
	switch first {
	case "SELECT", "WITH":
		verb = "SELECT"
	case "INSERT":
		verb = "INSERT"
	case "UPDATE":
		verb = "UPDATE"
	case "DELETE":
		verb = "DELETE"
	case "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "COMMENT":
		verb = "DDL"
	case "COPY", "LOAD", "BULK":
		verb = "EXPORT"
	default:
		verb = "OTHER"
	}
	seen := map[string]struct{}{}
	for _, m := range reSQLFrom.FindAllStringSubmatch(s, -1) {
		if len(m) < 2 {
			continue
		}
		t := normalizeTableRef(m[1])
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		tables = append(tables, t)
	}
	return verb, tables
}

func normalizeTableRef(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'`)
	raw = strings.ReplaceAll(raw, `"`, "")
	if i := strings.IndexAny(raw, "(\n\r\t "); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// MatchSQL returns whether the statement is allowed by the pack.
// Parse failure (no tables extracted for DML/DDL that needs them): allowlist denies; denylist allows (fail-open for deny patterns only).
func MatchSQL(pack SQLPack, statement string) (bool, string) {
	verb, tables := ClassifySQL(statement)
	if verb == "" {
		return true, ""
	}
	stmtOK := matchStatement(pack.Statements, verb)
	tableOK := matchTables(pack.Tables, tables)

	if pack.Mode == "denylist" {
		// deny if verb matches denylist statements OR any table matches denylist tables
		if len(pack.Statements) > 0 && stmtOK {
			return false, "statement denied by sql JEA: " + verb
		}
		if len(pack.Tables) > 0 && tableHit(pack.Tables, tables) {
			return false, "table denied by sql JEA"
		}
		return true, ""
	}
	// allowlist
	if len(pack.Statements) > 0 && !stmtOK {
		return false, "statement not allowed by sql JEA: " + verb
	}
	if len(pack.Tables) == 0 {
		return false, "sql JEA allowlist has no tables"
	}
	if len(tables) == 0 {
		// e.g. SELECT 1 — allow if statements permit
		return true, ""
	}
	if !tableOK {
		return false, "table not allowed by sql JEA"
	}
	return true, ""
}

func matchStatement(allowed []string, verb string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(a, verb) || a == "*" {
			return true
		}
	}
	return false
}

func tableHit(patterns, tables []string) bool {
	for _, t := range tables {
		for _, pat := range patterns {
			if matchTablePattern(pat, t) {
				return true
			}
		}
	}
	return false
}

func matchTables(patterns, tables []string) bool {
	if len(tables) == 0 {
		return true
	}
	for _, t := range tables {
		ok := false
		for _, pat := range patterns {
			if matchTablePattern(pat, t) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func matchTablePattern(pattern, table string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	table = strings.ToLower(strings.TrimSpace(table))
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, table)
	if err == nil && ok {
		return true
	}
	// also match bare name against schema.table
	if i := strings.LastIndex(table, "."); i >= 0 {
		bare := table[i+1:]
		ok, err = path.Match(pattern, bare)
		if err == nil && ok {
			return true
		}
	}
	return pattern == table
}

// MaskSQLResult redacts configured columns in-place style (returns new slices).
func MaskSQLResult(pack SQLPack, columns []string, rows [][]string) ([]string, [][]string) {
	if len(pack.MaskColumns) == 0 || len(columns) == 0 {
		return columns, rows
	}
	repl := pack.MaskReplacement
	if repl == "" {
		repl = "***"
	}
	idx := map[int]struct{}{}
	for i, c := range columns {
		cl := strings.ToLower(strings.TrimSpace(c))
		for _, m := range pack.MaskColumns {
			ml := strings.ToLower(strings.TrimSpace(m))
			if ml == "" {
				continue
			}
			if cl == ml || strings.HasSuffix(cl, "."+ml) || matchTablePattern(ml, cl) {
				idx[i] = struct{}{}
				break
			}
			if j := strings.LastIndex(ml, "."); j >= 0 && cl == ml[j+1:] {
				idx[i] = struct{}{}
				break
			}
		}
	}
	if len(idx) == 0 {
		return columns, rows
	}
	out := make([][]string, len(rows))
	for r, row := range rows {
		cp := append([]string(nil), row...)
		for i := range cp {
			if _, ok := idx[i]; ok {
				cp[i] = repl
			}
		}
		out[r] = cp
	}
	return columns, out
}
