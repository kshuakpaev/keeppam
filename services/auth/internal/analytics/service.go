package analytics

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db *store.DB
}

func New(db *store.DB) *Service {
	return &Service{db: db}
}

type Overview struct {
	WindowHours int          `json:"window_hours"`
	GeneratedAt time.Time    `json:"generated_at"`
	Stats       Stats        `json:"stats"`
	Series      Series       `json:"series"`
	Anomalies   []Anomaly    `json:"anomalies"`
	TopActors   []NamedCount `json:"top_actors"`
	TopAssets   []NamedCount `json:"top_assets"`
	SIEM        SIEMCorr     `json:"siem"`
	Chains      []Chain      `json:"chains"`
}

type Stats struct {
	LoginsOK         int `json:"logins_ok"`
	LoginsFail       int `json:"logins_fail"`
	SessionsStarted  int `json:"sessions_started"`
	SessionsActive   int `json:"sessions_active"`
	SessionsDenied   int `json:"sessions_denied"`
	SecretRotations  int `json:"secret_rotations"`
	JITRequests      int `json:"jit_requests"`
	OffHoursSessions int `json:"off_hours_sessions"`
	LongSessions     int `json:"long_sessions"`
	ForceKills       int `json:"force_kills"`
	AppAccess        int `json:"app_access"`
	SQLStatements    int `json:"sql_statements"`
}

type Series struct {
	LoginsByHour       []HourBucket `json:"logins_by_hour"`
	SessionsByProtocol []NamedCount `json:"sessions_by_protocol"`
	ActionsByType      []NamedCount `json:"actions_by_type"`
}

type HourBucket struct {
	Hour string `json:"hour"`
	OK   int    `json:"ok"`
	Fail int    `json:"fail"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Anomaly struct {
	Severity string `json:"severity"` // high|medium|low
	Code     string `json:"code"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Count    int    `json:"count"`
	Actor    string `json:"actor,omitempty"`
	Related  string `json:"related,omitempty"`
}

type SIEMCorr struct {
	Enabled       bool       `json:"enabled"`
	Transport     string     `json:"transport"`
	LastExportAt  *time.Time `json:"last_export_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	PendingEvents int        `json:"pending_events"`
	LagSeconds    *int64     `json:"lag_seconds,omitempty"`
	Healthy       bool       `json:"healthy"`
	Detail        string     `json:"detail"`
}

type Chain struct {
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Actor    string   `json:"actor,omitempty"`
	Steps    []string `json:"steps"`
	Count    int      `json:"count"`
}

type OverviewFilter struct {
	WindowHours int
	Severity    string // high|medium|low|"" 
	Code        string
}

func (s *Service) Overview(ctx context.Context, windowHours int) (Overview, error) {
	return s.OverviewFiltered(ctx, OverviewFilter{WindowHours: windowHours})
}

func (s *Service) OverviewFiltered(ctx context.Context, f OverviewFilter) (Overview, error) {
	windowHours := f.WindowHours
	if windowHours <= 0 || windowHours > 168 {
		windowHours = 24
	}
	now := time.Now().UTC()
	from := now.Add(-time.Duration(windowHours) * time.Hour)
	out := Overview{
		WindowHours: windowHours,
		GeneratedAt: now,
		Anomalies:   []Anomaly{},
		TopActors:   []NamedCount{},
		TopAssets:   []NamedCount{},
		Chains:      []Chain{},
		Series: Series{
			LoginsByHour:       []HourBucket{},
			SessionsByProtocol: []NamedCount{},
			ActionsByType:      []NamedCount{},
		},
	}

	pool := s.db.Pool
	var err error

	out.Stats.LoginsOK, err = countAction(ctx, pool, from, "user.login.success")
	if err != nil {
		return out, err
	}
	out.Stats.LoginsFail, err = countAction(ctx, pool, from, "user.login.failure")
	if err != nil {
		return out, err
	}
	out.Stats.SessionsStarted, err = countAction(ctx, pool, from, "session.started")
	if err != nil {
		return out, err
	}
	out.Stats.SessionsDenied, err = countAction(ctx, pool, from, "session.denied")
	if err != nil {
		return out, err
	}
	out.Stats.SecretRotations, err = countAction(ctx, pool, from, "asset.account.secret_rotated")
	if err != nil {
		return out, err
	}
	out.Stats.JITRequests, err = countAction(ctx, pool, from, "access.request.created")
	if err != nil {
		return out, err
	}
	out.Stats.ForceKills, err = countAction(ctx, pool, from, "session.ended")
	if err != nil {
		return out, err
	}
	// refine force kills: look for forced in payload via action session.ended with via api — approximate with session.ended count is noisy
	// use dedicated pattern from audit payload
	_ = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE ts >= $1 AND action='session.ended' AND payload->>'forced'='true'`, from).Scan(&out.Stats.ForceKills)
	out.Stats.AppAccess, err = countAction(ctx, pool, from, "app.access.granted")
	if err != nil {
		return out, err
	}
	out.Stats.SQLStatements, err = countAction(ctx, pool, from, "session.sql")
	if err != nil {
		return out, err
	}

	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE status='active'`).Scan(&out.Stats.SessionsActive); err != nil {
		return out, err
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE action='session.started' AND ts >= $1
		  AND EXTRACT(HOUR FROM ts AT TIME ZONE 'UTC') < 6`, from).Scan(&out.Stats.OffHoursSessions); err != nil {
		return out, err
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE (
			(status='active' AND COALESCE(started_at, created_at) < NOW() - INTERVAL '4 hours')
			OR (ended_at IS NOT NULL AND started_at IS NOT NULL AND ended_at - started_at > INTERVAL '4 hours'
			    AND COALESCE(ended_at, created_at) >= $1)
		)`, from).Scan(&out.Stats.LongSessions); err != nil {
		return out, err
	}

	out.Series.LoginsByHour, err = loginSeries(ctx, pool, from)
	if err != nil {
		return out, err
	}
	out.Series.SessionsByProtocol, err = protocolSeries(ctx, pool, from)
	if err != nil {
		return out, err
	}
	out.Series.ActionsByType, err = actionSeries(ctx, pool, from)
	if err != nil {
		return out, err
	}
	out.TopActors, err = topActors(ctx, pool, from)
	if err != nil {
		return out, err
	}
	out.TopAssets, err = topAssets(ctx, pool, from)
	if err != nil {
		return out, err
	}

	out.SIEM, err = siemCorrelation(ctx, pool, now)
	if err != nil {
		out.SIEM = SIEMCorr{Detail: "siem unavailable: " + err.Error(), Healthy: false}
	}

	bruteforce, _ := topLoginFailures(ctx, pool, from)
	multiAsset, _ := multiAssetActors(ctx, pool, from)

	out.Anomalies = detect(out.Stats, out.Series.LoginsByHour, windowHours, out.SIEM, bruteforce, multiAsset)
	out.Chains = buildChains(out.Anomalies, bruteforce, multiAsset, out.Stats)

	if f.Severity != "" {
		sev := strings.ToLower(f.Severity)
		filtered := out.Anomalies[:0]
		for _, a := range out.Anomalies {
			if a.Severity == sev {
				filtered = append(filtered, a)
			}
		}
		out.Anomalies = filtered
		cf := out.Chains[:0]
		for _, c := range out.Chains {
			if c.Severity == sev {
				cf = append(cf, c)
			}
		}
		out.Chains = cf
	}
	if f.Code != "" {
		code := f.Code
		filtered := out.Anomalies[:0]
		for _, a := range out.Anomalies {
			if a.Code == code {
				filtered = append(filtered, a)
			}
		}
		out.Anomalies = filtered
	}
	return out, nil
}

func countAction(ctx context.Context, pool *pgxpool.Pool, from time.Time, action string) (int, error) {
	var n int
	err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE action=$1 AND ts>=$2`, action, from).Scan(&n)
	return n, err
}

func loginSeries(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]HourBucket, error) {
	rows, err := pool.Query(ctx, `
		SELECT date_trunc('hour', ts) AS h,
			COUNT(*) FILTER (WHERE action='user.login.success') AS ok,
			COUNT(*) FILTER (WHERE action='user.login.failure') AS fail
		FROM audit_events
		WHERE ts >= $1 AND action IN ('user.login.success','user.login.failure')
		GROUP BY 1 ORDER BY 1`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HourBucket
	for rows.Next() {
		var h time.Time
		var b HourBucket
		if err := rows.Scan(&h, &b.OK, &b.Fail); err != nil {
			return nil, err
		}
		b.Hour = h.UTC().Format(time.RFC3339)
		out = append(out, b)
	}
	if out == nil {
		out = []HourBucket{}
	}
	return out, rows.Err()
}

func protocolSeries(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]NamedCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT protocol, COUNT(*) FROM sessions
		WHERE created_at >= $1
		GROUP BY protocol ORDER BY COUNT(*) DESC`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if out == nil {
		out = []NamedCount{}
	}
	return out, rows.Err()
}

func actionSeries(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]NamedCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT action, COUNT(*) FROM audit_events
		WHERE ts >= $1
		GROUP BY action ORDER BY COUNT(*) DESC LIMIT 12`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if out == nil {
		out = []NamedCount{}
	}
	return out, rows.Err()
}

func topActors(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]NamedCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(u.username, a.actor_id::text), COUNT(*)
		FROM audit_events a
		LEFT JOIN users u ON u.id = a.actor_id
		WHERE a.ts >= $1 AND a.action IN ('session.started','session.created')
		  AND a.actor_id IS NOT NULL
		GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 8`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if out == nil {
		out = []NamedCount{}
	}
	return out, rows.Err()
}

func topAssets(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]NamedCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(ast.name, s.asset_id::text), COUNT(*)
		FROM sessions s
		JOIN assets ast ON ast.id = s.asset_id
		WHERE s.created_at >= $1
		GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 8`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if out == nil {
		out = []NamedCount{}
	}
	return out, rows.Err()
}

func topLoginFailures(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]NamedCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(u.username, a.resource_id, a.ip, 'unknown'), COUNT(*)
		FROM audit_events a
		LEFT JOIN users u ON u.id = a.actor_id
		WHERE a.ts >= $1 AND a.action='user.login.failure'
		GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 5`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func multiAssetActors(ctx context.Context, pool *pgxpool.Pool, from time.Time) ([]NamedCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(u.username, s.user_id::text), COUNT(DISTINCT s.asset_id)
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.created_at >= $1
		GROUP BY 1
		HAVING COUNT(DISTINCT s.asset_id) >= 4
		ORDER BY COUNT(DISTINCT s.asset_id) DESC
		LIMIT 5`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NamedCount
	for rows.Next() {
		var c NamedCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func siemCorrelation(ctx context.Context, pool *pgxpool.Pool, now time.Time) (SIEMCorr, error) {
	var c SIEMCorr
	var lastExport *time.Time
	var cursorTS *time.Time
	err := pool.QueryRow(ctx, `
		SELECT enabled, transport, COALESCE(last_error,''), last_export_at, cursor_ts
		FROM siem_settings WHERE id=1`).Scan(&c.Enabled, &c.Transport, &c.LastError, &lastExport, &cursorTS)
	if err != nil {
		return c, err
	}
	c.LastExportAt = lastExport
	if cursorTS != nil {
		var pending int
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE ts > $1`, *cursorTS).Scan(&pending)
		c.PendingEvents = pending
		lag := int64(now.Sub(*cursorTS).Seconds())
		if lag < 0 {
			lag = 0
		}
		c.LagSeconds = &lag
	} else if c.Enabled {
		var pending int
		_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&pending)
		c.PendingEvents = pending
	}

	switch {
	case !c.Enabled || c.Transport == "off":
		c.Healthy = true
		c.Detail = "SIEM выключен"
	case c.LastError != "":
		c.Healthy = false
		c.Detail = "ошибка экспорта: " + c.LastError
	case c.PendingEvents > 500:
		c.Healthy = false
		c.Detail = fmt.Sprintf("очередь экспорта %d событий", c.PendingEvents)
	case c.LagSeconds != nil && *c.LagSeconds > 900:
		c.Healthy = false
		c.Detail = fmt.Sprintf("лаг курсора %ds", *c.LagSeconds)
	default:
		c.Healthy = true
		c.Detail = "экспорт в норме"
	}
	return c, nil
}

func detect(stats Stats, hours []HourBucket, windowHours int, siem SIEMCorr, bruteforce, multiAsset []NamedCount) []Anomaly {
	var out []Anomaly
	if stats.LoginsFail >= 20 || (windowHours <= 24 && stats.LoginsFail >= 10 && stats.LoginsFail > stats.LoginsOK) {
		out = append(out, Anomaly{
			Severity: "high", Code: "login_failures", Title: "Всплеск неудачных входов",
			Detail: fmt.Sprintf("%d неудачных входов за %d ч (успешных: %d)", stats.LoginsFail, windowHours, stats.LoginsOK),
			Count:  stats.LoginsFail,
		})
	}
	for _, h := range hours {
		if h.Fail >= 8 {
			out = append(out, Anomaly{
				Severity: "high", Code: "login_failures_hour", Title: "Много неудачных входов за час",
				Detail: fmt.Sprintf("%s — %d неудач", h.Hour, h.Fail), Count: h.Fail,
			})
			break
		}
	}
	for _, b := range bruteforce {
		if b.Count >= 8 {
			out = append(out, Anomaly{
				Severity: "high", Code: "brute_force_actor", Title: "Возможный brute-force",
				Detail: fmt.Sprintf("%s — %d неудачных входов", b.Name, b.Count),
				Count:  b.Count, Actor: b.Name,
			})
		}
	}
	for _, m := range multiAsset {
		out = append(out, Anomaly{
			Severity: "medium", Code: "multi_asset_burst", Title: "Доступ ко многим активам",
			Detail: fmt.Sprintf("%s — %d разных активов за окно", m.Name, m.Count),
			Count:  m.Count, Actor: m.Name,
		})
	}
	if stats.OffHoursSessions >= 3 {
		out = append(out, Anomaly{
			Severity: "medium", Code: "off_hours_sessions", Title: "Сессии в нерабочие часы (UTC 00–06)",
			Detail: fmt.Sprintf("%d стартов сессий ночью за %d ч", stats.OffHoursSessions, windowHours),
			Count:  stats.OffHoursSessions,
		})
	}
	if stats.LongSessions >= 1 {
		out = append(out, Anomaly{
			Severity: "medium", Code: "long_sessions", Title: "Долгие сессии (>4 ч)",
			Detail: fmt.Sprintf("%d сессий дольше 4 часов", stats.LongSessions), Count: stats.LongSessions,
		})
	}
	if stats.SessionsDenied >= 5 {
		out = append(out, Anomaly{
			Severity: "medium", Code: "session_denials", Title: "Частые отказы по политике",
			Detail: fmt.Sprintf("%d session.denied за %d ч", stats.SessionsDenied, windowHours),
			Count:  stats.SessionsDenied,
		})
	}
	if stats.SecretRotations >= 10 {
		out = append(out, Anomaly{
			Severity: "medium", Code: "rotation_spike", Title: "Много ротаций секретов",
			Detail: fmt.Sprintf("%d ротаций за %d ч", stats.SecretRotations, windowHours),
			Count:  stats.SecretRotations,
		})
	}
	if stats.ForceKills >= 3 {
		out = append(out, Anomaly{
			Severity: "medium", Code: "force_kills", Title: "Принудительные завершения сессий",
			Detail: fmt.Sprintf("%d forced session.ended", stats.ForceKills), Count: stats.ForceKills,
		})
	}
	if stats.SQLStatements >= 100 {
		out = append(out, Anomaly{
			Severity: "low", Code: "sql_volume", Title: "Высокий объём SQL через PAM",
			Detail: fmt.Sprintf("%d session.sql за окно", stats.SQLStatements), Count: stats.SQLStatements,
		})
	}
	if siem.Enabled && siem.Transport != "off" && !siem.Healthy {
		out = append(out, Anomaly{
			Severity: "high", Code: "siem_lag", Title: "Проблема SIEM-экспорта",
			Detail: siem.Detail, Count: siem.PendingEvents, Related: "siem",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		rank := map[string]int{"high": 0, "medium": 1, "low": 2}
		return rank[out[i].Severity] < rank[out[j].Severity]
	})
	if out == nil {
		out = []Anomaly{}
	}
	return out
}

func buildChains(anoms []Anomaly, bruteforce, multiAsset []NamedCount, stats Stats) []Chain {
	var out []Chain
	// Correlate: brute-force actor who also has multi-asset or session denials
	actorsBF := map[string]int{}
	for _, b := range bruteforce {
		if b.Count >= 5 {
			actorsBF[b.Name] = b.Count
		}
	}
	for _, m := range multiAsset {
		if n, ok := actorsBF[m.Name]; ok {
			out = append(out, Chain{
				Severity: "high",
				Title:    "Brute-force → lateral asset access",
				Detail:   fmt.Sprintf("%s: %d login fail, затем %d активов", m.Name, n, m.Count),
				Actor:    m.Name,
				Steps:    []string{"user.login.failure×N", "session.started на нескольких активах"},
				Count:    n + m.Count,
			})
		}
	}
	hasLoginFail := false
	hasDeny := false
	hasSIEM := false
	for _, a := range anoms {
		switch a.Code {
		case "login_failures", "brute_force_actor", "login_failures_hour":
			hasLoginFail = true
		case "session_denials":
			hasDeny = true
		case "siem_lag":
			hasSIEM = true
		}
	}
	if hasLoginFail && hasDeny {
		out = append(out, Chain{
			Severity: "high",
			Title:    "Неудачные входы + отказы политики",
			Detail:   "Возможный перебор учёток и попытки обхода ACL",
			Steps:    []string{"user.login.failure", "session.denied"},
			Count:    stats.LoginsFail + stats.SessionsDenied,
		})
	}
	if hasSIEM && (hasLoginFail || stats.SessionsStarted > 0) {
		out = append(out, Chain{
			Severity: "high",
			Title:    "Активность при отставании SIEM",
			Detail:   "События безопасности могут не дойти до коррелятора",
			Steps:    []string{"audit activity", "siem export lag/error"},
			Count:    1,
		})
	}
	if out == nil {
		out = []Chain{}
	}
	return out
}
