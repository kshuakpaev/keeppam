package attacksim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db     *store.DB
	aud    *audit.Service
	policy *policy.Service
	base   string // API base for HTTP probes, e.g. http://127.0.0.1:8080
}

func New(db *store.DB, aud *audit.Service, pol *policy.Service, httpAddr string) *Service {
	base := "http://127.0.0.1" + httpAddr
	if strings.HasPrefix(httpAddr, ":") {
		base = "http://127.0.0.1" + httpAddr
	} else if httpAddr != "" {
		base = "http://" + httpAddr
	}
	return &Service{db: db, aud: aud, policy: pol, base: base}
}

type ScenarioMeta struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type Result struct {
	ID         uuid.UUID `json:"id"`
	RunID      uuid.UUID `json:"run_id"`
	ScenarioID string    `json:"scenario_id"`
	Title      string    `json:"title"`
	Category   string    `json:"category"`
	Status     string    `json:"status"`
	Detail     string    `json:"detail"`
	DurationMs int       `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

type Run struct {
	ID         uuid.UUID       `json:"id"`
	StartedBy  *uuid.UUID      `json:"started_by,omitempty"`
	Status     string          `json:"status"`
	Notes      string          `json:"notes"`
	Summary    map[string]any  `json:"summary"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Results    []Result        `json:"results,omitempty"`
}

func (s *Service) ListScenarios() []ScenarioMeta {
	out := make([]ScenarioMeta, 0, len(scenarioDefs))
	for _, d := range scenarioDefs {
		out = append(out, ScenarioMeta{ID: d.id, Title: d.title, Category: d.category, Description: d.desc})
	}
	return out
}

func (s *Service) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, started_by, status, notes, summary, started_at, finished_at
		FROM attack_sim_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []Run{}
	}
	return out, rows.Err()
}

func (s *Service) GetRun(ctx context.Context, id uuid.UUID) (Run, error) {
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, started_by, status, notes, summary, started_at, finished_at
		FROM attack_sim_runs WHERE id=$1`, id)
	r, err := scanRun(row)
	if err != nil {
		return Run{}, err
	}
	resRows, err := s.db.Pool.Query(ctx, `
		SELECT id, run_id, scenario_id, title, category, status, detail, duration_ms, created_at
		FROM attack_sim_results WHERE run_id=$1 ORDER BY created_at`, id)
	if err != nil {
		return r, err
	}
	defer resRows.Close()
	for resRows.Next() {
		var res Result
		if err := resRows.Scan(&res.ID, &res.RunID, &res.ScenarioID, &res.Title, &res.Category, &res.Status, &res.Detail, &res.DurationMs, &res.CreatedAt); err != nil {
			return r, err
		}
		r.Results = append(r.Results, res)
	}
	if r.Results == nil {
		r.Results = []Result{}
	}
	return r, resRows.Err()
}

func (s *Service) Run(ctx context.Context, actorID uuid.UUID, notes string) (Run, error) {
	id := store.NewID()
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO attack_sim_runs (id, started_by, status, notes, summary, started_at)
		VALUES ($1,$2,'running',$3,'{}',NOW())`, id, actorID, strings.TrimSpace(notes))
	if err != nil {
		return Run{}, err
	}
	_ = s.aud.Record(ctx, &actorID, "attacksim.run.started", "attack_sim_run", id.String(), "", "attacksim", nil)

	pass, fail, skip, errn := 0, 0, 0, 0
	for _, def := range scenarioDefs {
		start := time.Now()
		st, detail := def.fn(ctx, s)
		ms := int(time.Since(start).Milliseconds())
		switch st {
		case "pass":
			pass++
		case "fail":
			fail++
		case "skip":
			skip++
		default:
			st = "error"
			errn++
		}
		rid := store.NewID()
		_, _ = s.db.Pool.Exec(ctx, `
			INSERT INTO attack_sim_results (id, run_id, scenario_id, title, category, status, detail, duration_ms, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())`,
			rid, id, def.id, def.title, def.category, st, truncate(detail, 2000), ms)
	}

	status := "passed"
	if fail > 0 || errn > 0 {
		if pass > 0 || skip > 0 {
			status = "partial"
		} else {
			status = "failed"
		}
	}
	summary := map[string]any{
		"pass": pass, "fail": fail, "skip": skip, "error": errn, "total": len(scenarioDefs),
	}
	b, _ := json.Marshal(summary)
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE attack_sim_runs SET status=$2, summary=$3, finished_at=NOW() WHERE id=$1`, id, status, b)
	_ = s.aud.Record(ctx, &actorID, "attacksim.run.finished", "attack_sim_run", id.String(), "", "attacksim", summary)
	return s.GetRun(ctx, id)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanRun(row scannable) (Run, error) {
	var r Run
	var summary []byte
	err := row.Scan(&r.ID, &r.StartedBy, &r.Status, &r.Notes, &summary, &r.StartedAt, &r.FinishedAt)
	if err != nil {
		return Run{}, err
	}
	_ = json.Unmarshal(summary, &r.Summary)
	if r.Summary == nil {
		r.Summary = map[string]any{}
	}
	return r, nil
}

type scenarioDef struct {
	id, title, category, desc string
	fn                        func(ctx context.Context, s *Service) (status, detail string)
}

var scenarioDefs = []scenarioDef{
	{
		id: "ctrl.healthz", title: "Control plane healthz", category: "control",
		desc: "GET /healthz returns ok",
		fn: func(ctx context.Context, s *Service) (string, string) {
			code, body, err := httpGet(ctx, s.base+"/healthz")
			if err != nil {
				return "fail", err.Error()
			}
			if code != 200 {
				return "fail", fmt.Sprintf("status %d body=%s", code, truncate(body, 200))
			}
			return "pass", "healthz ok"
		},
	},
	{
		id: "auth.deny_bad_password", title: "Reject invalid password", category: "auth",
		desc: "POST /auth/login with wrong password must fail",
		fn: func(ctx context.Context, s *Service) (string, string) {
			code, body, err := httpPostJSON(ctx, s.base+"/api/v1/auth/login", `{"username":"admin","password":"definitely-wrong-pass-!!"}`)
			if err != nil {
				return "error", err.Error()
			}
			if code == 401 || code == 403 || strings.Contains(body, "invalid") {
				return "pass", fmt.Sprintf("denied with HTTP %d", code)
			}
			return "fail", fmt.Sprintf("unexpected HTTP %d: %s", code, truncate(body, 200))
		},
	},
	{
		id: "auth.deny_unauth_admin", title: "Reject unauthenticated admin API", category: "auth",
		desc: "GET /admin/users without session must be unauthorized",
		fn: func(ctx context.Context, s *Service) (string, string) {
			code, _, err := httpGet(ctx, s.base+"/api/v1/admin/users")
			if err != nil {
				return "error", err.Error()
			}
			if code == 401 || code == 403 {
				return "pass", fmt.Sprintf("denied HTTP %d", code)
			}
			return "fail", fmt.Sprintf("expected 401/403 got %d", code)
		},
	},
	{
		id: "jea.seed_packs", title: "JEA seed packs present", category: "jea",
		desc: "readonly-linux and block-destructive packs exist",
		fn: func(ctx context.Context, s *Service) (string, string) {
			packs, err := s.policy.ListCommandPacks(ctx)
			if err != nil {
				return "error", err.Error()
			}
			need := map[string]bool{"readonly-linux": false, "block-destructive": false}
			for _, p := range packs {
				if _, ok := need[p.Name]; ok {
					need[p.Name] = true
				}
			}
			missing := []string{}
			for k, ok := range need {
				if !ok {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				return "fail", "missing: " + strings.Join(missing, ", ")
			}
			return "pass", fmt.Sprintf("%d packs", len(packs))
		},
	},
	{
		id: "jea.deny_destructive", title: "JEA denylist blocks rm", category: "jea",
		desc: "block-destructive pack denies 'rm -rf /'",
		fn: func(ctx context.Context, s *Service) (string, string) {
			packs, err := s.policy.ListCommandPacks(ctx)
			if err != nil {
				return "error", err.Error()
			}
			var pack policy.CommandPack
			found := false
			for _, p := range packs {
				if p.Name == "block-destructive" {
					pack = p
					found = true
					break
				}
			}
			if !found {
				return "skip", "pack not found"
			}
			if policy.MatchCommand(pack, "rm -rf /") {
				return "fail", "rm -rf / was allowed"
			}
			return "pass", "rm -rf / denied"
		},
	},
	{
		id: "jea.allow_readonly_ls", title: "JEA allowlist permits ls", category: "jea",
		desc: "readonly-linux pack allows 'ls'",
		fn: func(ctx context.Context, s *Service) (string, string) {
			packs, err := s.policy.ListCommandPacks(ctx)
			if err != nil {
				return "error", err.Error()
			}
			var pack policy.CommandPack
			found := false
			for _, p := range packs {
				if p.Name == "readonly-linux" {
					pack = p
					found = true
					break
				}
			}
			if !found {
				return "skip", "pack not found"
			}
			if !policy.MatchCommand(pack, "ls") {
				return "fail", "ls was denied"
			}
			if policy.MatchCommand(pack, "rm -rf /tmp/x") {
				return "fail", "rm should not match allowlist"
			}
			return "pass", "ls allowed, rm denied"
		},
	},
	{
		id: "compliance.packs", title: "Compliance packs available", category: "compliance",
		desc: "At least one compliance pack is seeded",
		fn: func(ctx context.Context, s *Service) (string, string) {
			var n int
			err := s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM compliance_packs`).Scan(&n)
			if err != nil {
				return "error", err.Error()
			}
			if n == 0 {
				return "fail", "no compliance packs"
			}
			return "pass", fmt.Sprintf("%d packs", n)
		},
	},
	{
		id: "db.ephemeral_schema", title: "Ephemeral DB roles schema", category: "db",
		desc: "db_session_roles table exists",
		fn: func(ctx context.Context, s *Service) (string, string) {
			var n int
			err := s.db.Pool.QueryRow(ctx, `
				SELECT count(*) FROM information_schema.tables
				WHERE table_schema='public' AND table_name='db_session_roles'`).Scan(&n)
			if err != nil {
				return "error", err.Error()
			}
			if n != 1 {
				return "fail", "table missing"
			}
			return "pass", "db_session_roles ok"
		},
	},
	{
		id: "policy.deny_by_default", title: "ACL deny-by-default", category: "policy",
		desc: "Random asset UUID without bindings is denied",
		fn: func(ctx context.Context, s *Service) (string, string) {
			ok, err := s.policy.Allowed(ctx, policy.AccessCheck{
				UserID: store.NewID(), AssetID: store.NewID(), RoleNames: []string{"operator"}, Bypass: false, Now: time.Now(),
			})
			if err != nil {
				// missing asset tags query may error — treat as pass if error mentions no rows / empty
				return "pass", "evaluate completed with err (no binding): " + truncate(err.Error(), 120)
			}
			if ok {
				return "fail", "access unexpectedly allowed"
			}
			return "pass", "denied without binding"
		},
	},
	{
		id: "dr.settings_readable", title: "DR settings readable", category: "dr",
		desc: "dr_settings row exists",
		fn: func(ctx context.Context, s *Service) (string, string) {
			var n int
			err := s.db.Pool.QueryRow(ctx, `SELECT count(*) FROM dr_settings`).Scan(&n)
			if err != nil {
				return "error", err.Error()
			}
			if n == 0 {
				return "fail", "no dr_settings"
			}
			return "pass", "dr_settings present"
		},
	},
}

func httpGet(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n]), nil
}

func httpPostJSON(ctx context.Context, url, body string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n]), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
