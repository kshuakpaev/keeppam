package uebaml

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/guacindex"
	"github.com/keeppam/auth/internal/notify"
	"github.com/keeppam/auth/internal/sessionsvc"
	"github.com/keeppam/auth/internal/store"
	"github.com/keeppam/auth/internal/ueba"
)

type Settings struct {
	Mode          string     `json:"mode"`
	PeerGroup     bool       `json:"peer_group"`
	MLThreshold   int        `json:"ml_threshold"`
	LiveIntervalS int        `json:"live_interval_s"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

type ConnectResult struct {
	MLScore      float64  `json:"ml_score"`
	Threshold    int      `json:"threshold"`
	PeerGroup    string   `json:"peer_group,omitempty"`
	PeerRatio    float64  `json:"peer_ratio,omitempty"`
	PeerMembers  int      `json:"peer_members,omitempty"`
	AddedScore   int      `json:"added_score"`
	AddedFactors []string `json:"added_factors,omitempty"`
}

type Service struct {
	db     *store.DB
	aud    *audit.Service
	sess   *sessionsvc.Service
	notify *notify.Service
}

func New(db *store.DB, aud *audit.Service, sess *sessionsvc.Service, notify *notify.Service) *Service {
	return &Service{db: db, aud: aud, sess: sess, notify: notify}
}

func NormalizeMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return "off", nil
	case "audit":
		return "audit", nil
	case "live":
		return "live", nil
	default:
		return "", fmt.Errorf("ueba ml mode must be off, audit, or live")
	}
}

func (s *Service) Enabled(ctx context.Context) bool {
	cfg, err := s.load(ctx)
	return err == nil && cfg.Mode != "off"
}

func (s *Service) LiveEnabled(ctx context.Context) bool {
	cfg, err := s.load(ctx)
	return err == nil && cfg.Mode == "live"
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	return s.load(ctx)
}

func (s *Service) load(ctx context.Context) (Settings, error) {
	var out Settings
	var updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(mode,'off'), COALESCE(peer_group,TRUE), COALESCE(ml_threshold,65),
			COALESCE(live_interval_s,60), last_run_at, COALESCE(last_error,''), updated_at
		FROM ueba_ml_settings WHERE id=1`).Scan(
		&out.Mode, &out.PeerGroup, &out.MLThreshold, &out.LiveIntervalS,
		&out.LastRunAt, &out.LastError, &updatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return Settings{Mode: "off", PeerGroup: true, MLThreshold: DefaultThreshold, LiveIntervalS: 60}, nil
		}
		return Settings{}, err
	}
	if out.MLThreshold < 30 {
		out.MLThreshold = DefaultThreshold
	}
	out.UpdatedAt = &updatedAt
	return out, nil
}

func (s *Service) Put(ctx context.Context, actorID uuid.UUID, in Settings, ip, ua string) (Settings, error) {
	mode, err := NormalizeMode(in.Mode)
	if err != nil {
		return Settings{}, err
	}
	th := in.MLThreshold
	if th <= 0 {
		th = DefaultThreshold
	}
	if th < 30 || th > 95 {
		return Settings{}, fmt.Errorf("ml_threshold must be 30..95")
	}
	interval := in.LiveIntervalS
	if interval <= 0 {
		interval = 60
	}
	if interval < 15 || interval > 600 {
		return Settings{}, fmt.Errorf("live_interval_s must be 15..600")
	}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO ueba_ml_settings (id, mode, peer_group, ml_threshold, live_interval_s, updated_at)
		VALUES (1,$1,$2,$3,$4,NOW())
		ON CONFLICT (id) DO UPDATE SET
			mode=EXCLUDED.mode, peer_group=EXCLUDED.peer_group,
			ml_threshold=EXCLUDED.ml_threshold, live_interval_s=EXCLUDED.live_interval_s,
			updated_at=NOW()`, mode, in.PeerGroup, th, interval)
	if err != nil {
		return Settings{}, err
	}
	if s.aud != nil {
		_ = s.aud.Record(ctx, &actorID, "ueba_ml.settings.updated", "ueba_ml", "1", ip, ua, map[string]any{
			"mode": mode, "peer_group": in.PeerGroup, "threshold": th,
		})
	}
	return s.Get(ctx)
}

func (s *Service) buildFeatures(ctx context.Context, userID, assetID uuid.UUID, now time.Time, cfg Settings, ikiZ, mouseZ float64) (Features, PeerGroup, error) {
	var f Features
	var pg PeerGroup
	inputs, err := s.loadConnectInputs(ctx, userID, assetID, now)
	if err != nil {
		return f, pg, err
	}
	if inputs.UnusualAsset {
		f.UnusualAsset = 1
	}
	if inputs.SpreadBurst {
		f.SpreadBurst = 1
	}
	f.FailedLogins = float64(inputs.FailedLogins24h) / 10
	f.Concurrent = float64(inputs.ConcurrentActive)
	if now.UTC().Hour() < 6 {
		f.OffHours = 1
	}
	f.KeystrokeZ = ikiZ
	f.MouseZ = mouseZ
	if cfg.PeerGroup {
		pg, err = loadPeerGroup(ctx, s.db.Pool, userID)
		if err == nil && pg.Members > 0 && assetID != uuid.Nil {
			ratio, _, err := PeerAssetAccessRatio(ctx, s.db.Pool, pg.ID, assetID, ueba.BaselineFrom(now))
			if err == nil {
				f.PeerAssetRare = 1 - ratio
			}
		}
	}
	return f, pg, nil
}

type connectInputs struct {
	FailedLogins24h  int
	ConcurrentActive int
	UnusualAsset     bool
	SpreadBurst      bool
}

func (s *Service) loadConnectInputs(ctx context.Context, userID, assetID uuid.UUID, now time.Time) (connectInputs, error) {
	var in connectInputs
	from := now.UTC().Add(-24 * time.Hour)
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE action='user.login.failure' AND ts >= $1
		  AND (resource_id=(SELECT username FROM users WHERE id=$2) OR actor_id=$2)`,
		from, userID).Scan(&in.FailedLogins24h)
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE user_id=$1 AND status IN ('pending','active')`, userID).Scan(&in.ConcurrentActive)
	baselineFrom := ueba.BaselineFrom(now)
	var n24, baseline int
	var seen30 bool
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT
			COUNT(DISTINCT asset_id) FILTER (WHERE created_at >= $2),
			COUNT(DISTINCT asset_id),
			COALESCE(BOOL_OR(asset_id = $3), false)
		FROM sessions
		WHERE user_id=$1 AND created_at >= $4 AND `+ueba.SessionSQL,
		userID, from, assetID, baselineFrom).Scan(&n24, &baseline, &seen30)
	recent := n24
	if assetID != uuid.Nil {
		var seen24 bool
		_ = s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(BOOL_OR(asset_id = $2 AND created_at >= $3), false)
			FROM sessions WHERE user_id=$1 AND `+ueba.SessionSQL,
			userID, assetID, from).Scan(&seen24)
		if !seen24 {
			recent++
		}
	}
	in.UnusualAsset = ueba.NewAsset(baseline, seen30)
	in.SpreadBurst = ueba.Spread(baseline, recent)
	return in, nil
}

// EnhanceConnect adjusts connect risk score using peer-group + ML composite.
func (s *Service) EnhanceConnect(ctx context.Context, userID, assetID uuid.UUID, score int, factors []string) (int, []string, ConnectResult, error) {
	out := ConnectResult{Threshold: DefaultThreshold}
	cfg, err := s.load(ctx)
	if err != nil || cfg.Mode == "off" {
		return score, factors, out, err
	}
	out.Threshold = cfg.MLThreshold
	f, pg, err := s.buildFeatures(ctx, userID, assetID, time.Now(), cfg, 0, 0)
	if err != nil {
		return score, factors, out, err
	}
	ml := MLScore(f)
	out.MLScore = ml
	if pg.Name != "" {
		out.PeerGroup = pg.Name
		out.PeerMembers = pg.Members
		if cfg.PeerGroup && assetID != uuid.Nil {
			ratio, _, _ := PeerAssetAccessRatio(ctx, s.db.Pool, pg.ID, assetID, ueba.BaselineFrom(time.Now()))
			out.PeerRatio = ratio
		}
	}
	added := 0
	var addedFactors []string
	has := func(code string) bool {
		for _, x := range factors {
			if x == code {
				return true
			}
		}
		return false
	}
	if cfg.PeerGroup && peerOutlier(out.PeerRatio, out.PeerMembers) && !has(FactorPeerOutlier) {
		added += PeerOutlierPoints
		addedFactors = append(addedFactors, FactorPeerOutlier)
	}
	if ml >= float64(cfg.MLThreshold) && !has(FactorMLHigh) {
		added += MLHighPoints
		addedFactors = append(addedFactors, FactorMLHigh)
	}
	if added == 0 {
		return score, factors, out, nil
	}
	score += added
	if score > 100 {
		score = 100
	}
	factors = append(append([]string{}, factors...), addedFactors...)
	out.AddedScore = added
	out.AddedFactors = addedFactors
	return score, factors, out, nil
}

// ScorePostSession enriches post-session keystroke/mouse UEBA with peer + ML layer.
func (s *Service) ScorePostSession(ctx context.Context, row sessionsvc.Session, ikiZ, mouseZ float64) (mlScore float64, extraFactors []string) {
	cfg, err := s.load(ctx)
	if err != nil || cfg.Mode == "off" {
		return 0, nil
	}
	f, _, err := s.buildFeatures(ctx, row.UserID, row.AssetID, time.Now(), cfg, ikiZ, mouseZ)
	if err != nil {
		return 0, nil
	}
	ml := MLScore(f)
	if ml >= float64(cfg.MLThreshold) {
		extraFactors = append(extraFactors, FactorMLHigh)
	}
	return ml, extraFactors
}

func (s *Service) recordLiveRun(ctx context.Context, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, _ = s.db.Pool.Exec(ctx, `
		UPDATE ueba_ml_settings SET last_run_at=NOW(), last_error=$1, updated_at=NOW() WHERE id=1`, msg)
}

// RunLive periodically scores active graphical sessions from partial guac recordings.
func (s *Service) RunLive(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.liveTick(ctx)
		}
	}
}

func (s *Service) liveTick(ctx context.Context) {
	cfg, err := s.load(ctx)
	if err != nil || cfg.Mode != "live" {
		return
	}
	interval := time.Duration(cfg.LiveIntervalS) * time.Second
	if cfg.LastRunAt != nil && time.Since(*cfg.LastRunAt) < interval {
		return
	}
	err = s.scanActiveSessions(ctx, cfg)
	s.recordLiveRun(ctx, err)
}

func (s *Service) scanActiveSessions(ctx context.Context, cfg Settings) error {
	if s.sess == nil {
		return nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, asset_id, protocol, recording_path
		FROM sessions
		WHERE status='active' AND protocol IN ('rdp','vnc','https','citrix')
		  AND recording_path <> ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, userID, assetID uuid.UUID
		var protocol, recPath string
		if err := rows.Scan(&id, &userID, &assetID, &protocol, &recPath); err != nil {
			return err
		}
		if err := s.liveSession(ctx, cfg, id, userID, assetID, recPath); err != nil {
			slog.Warn("ueba ml live", "session", id.String(), "err", err)
		}
	}
	return rows.Err()
}

func (s *Service) liveSession(ctx context.Context, cfg Settings, sessionID, userID, assetID uuid.UUID, recPath string) error {
	if s.alreadyLiveFlagged(ctx, sessionID) {
		return nil
	}
	path, err := s.sess.RecordingFile(ctx, sessionID)
	if err != nil {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	_, tim, mouse, err := guacindex.ParseKeysMouseAndTiming(f)
	if err != nil {
		return err
	}
	row, err := s.sess.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	var ikiZ, mouseZ float64
	if tim.NKeys >= ueba.MinKeystrokeKeys && tim.MedianMs > 0 {
		since := ueba.BaselineFrom(time.Now())
		medians, _ := s.sess.KeystrokeMedians(ctx, userID, since, sessionID)
		mean, std := ueba.MeanStd(medians)
		ikiZ = ueba.ZScore(tim.MedianMs, mean, std)
		if ueba.FastTyping(tim.MedianMs, tim.NKeys, len(medians), mean, std, ikiZ) {
			ml, _ := s.ScorePostSession(ctx, row, ikiZ, 0)
			return s.flagLive(ctx, row, tim.MedianMs, ikiZ, ml, "keystroke")
		}
	}
	if mouse.NMoves >= ueba.MinMouseMoves && mouse.MedianVel > 0 {
		since := ueba.BaselineFrom(time.Now())
		vels, _ := s.sess.MouseVelMedians(ctx, userID, since, sessionID)
		mean, std := ueba.MeanStd(vels)
		mouseZ = ueba.ZScore(mouse.MedianVel, mean, std)
		if ueba.FastMouse(mouse.MedianVel, mouse.NMoves, mouse.Samples, len(vels), mean, std, mouseZ) {
			ml, _ := s.ScorePostSession(ctx, row, 0, mouseZ)
			return s.flagLive(ctx, row, mouse.MedianVel, mouseZ, ml, "mouse")
		}
	}
	_ = assetID
	_ = recPath
	_ = cfg
	_ = ikiZ
	_ = mouseZ
	return nil
}

func (s *Service) alreadyLiveFlagged(ctx context.Context, sessionID uuid.UUID) bool {
	var n int
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_events
		WHERE session_id=$1 AND event_type='ueba' AND payload->>'factor'=$2`,
		sessionID, FactorLiveFast).Scan(&n)
	return n > 0
}

func (s *Service) flagLive(ctx context.Context, row sessionsvc.Session, metric, z, ml float64, kind string) error {
	score, factors, err := s.sess.AppendRisk(ctx, row.ID, LiveFastPoints, FactorLiveFast)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"factor": FactorLiveFast, "kind": kind, "metric": metric, "z": z,
		"ml_score": ml, "live": true, "risk_score": score, "risk_factors": factors,
	}
	_ = s.sess.AddEvent(ctx, row.ID, "ueba", payload)
	_ = s.sess.AddEvent(ctx, row.ID, "risk", payload)
	if s.notify != nil {
		s.notify.OnUEBAAnomaly(ctx, row, payload)
	}
	return nil
}
