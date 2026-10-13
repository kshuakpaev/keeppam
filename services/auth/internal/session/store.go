package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Session struct {
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	Roles        []string  `json:"roles"`
	Permissions  []string  `json:"permissions"`
	SAMLNameID   string    `json:"saml_name_id,omitempty"`
	SAMLIdP      string    `json:"saml_idp,omitempty"`
	Devices      []string  `json:"devices,omitempty"`
	LastActivity time.Time `json:"last_activity,omitempty"`
}

type Challenge struct {
	UserID    uuid.UUID `json:"user_id"`
	Username  string    `json:"username"`
	Purpose   string    `json:"purpose,omitempty"` // "" = login, "stepup"
	AssetID   string    `json:"asset_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

type StepUpGrant struct {
	UserID    uuid.UUID `json:"user_id"`
	AssetID   uuid.UUID `json:"asset_id"`
	SessionID uuid.UUID `json:"session_id,omitempty"`
}

type OpStepUpPending struct {
	ChallengeToken string   `json:"challenge_token"`
	TOTP           bool     `json:"totp"`
	WebAuthn       bool     `json:"webauthn"`
	RiskScore      int      `json:"risk_score"`
	MaxRisk        int      `json:"max_risk"`
	RiskFactors    []string `json:"risk_factors"`
	Operation      string   `json:"operation,omitempty"`
}

type Store struct {
	rdb *redis.Client
}

func Connect(url string) (*Store, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}
	return &Store{rdb: rdb}, nil
}

func (s *Store) Close() error {
	return s.rdb.Close()
}

func (s *Store) Redis() *redis.Client {
	return s.rdb
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Store) Create(ctx context.Context, sess Session, ttl time.Duration) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if sess.LastActivity.IsZero() {
		sess.LastActivity = time.Now().UTC()
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	if err := s.rdb.Set(ctx, "sess:"+token, data, ttl).Err(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) Get(ctx context.Context, token string) (Session, error) {
	var sess Session
	data, err := s.rdb.Get(ctx, "sess:"+token).Bytes()
	if err != nil {
		return sess, err
	}
	err = json.Unmarshal(data, &sess)
	return sess, err
}

func (s *Store) Update(ctx context.Context, token string, sess Session) error {
	ttl, err := s.rdb.TTL(ctx, "sess:"+token).Result()
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, "sess:"+token, data, ttl).Err()
}

func (s *Store) Delete(ctx context.Context, token string) error {
	return s.rdb.Del(ctx, "sess:"+token).Err()
}

func (s *Store) CreateChallenge(ctx context.Context, c Challenge, ttl time.Duration) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if err := s.rdb.Set(ctx, "chal:"+token, data, ttl).Err(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) GetChallenge(ctx context.Context, token string) (Challenge, error) {
	var c Challenge
	data, err := s.rdb.Get(ctx, "chal:"+token).Bytes()
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(data, &c)
	return c, err
}

func (s *Store) DeleteChallenge(ctx context.Context, token string) error {
	return s.rdb.Del(ctx, "chal:"+token).Err()
}

func (s *Store) IncrLoginFail(ctx context.Context, key string, window time.Duration) (int64, error) {
	pipe := s.rdb.Pipeline()
	incr := pipe.Incr(ctx, "rl:"+key)
	pipe.Expire(ctx, "rl:"+key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (s *Store) ResetLoginFail(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, "rl:"+key).Err()
}

func CSRFToken() (string, error) {
	return newToken()
}

func (s *Store) PutJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, key, data, ttl).Err()
}

func (s *Store) GetJSON(ctx context.Context, key string, dest any) error {
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

func (s *Store) DeleteKey(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, key).Err()
}

func (s *Store) ConsumeJSON(ctx context.Context, key string, dest any) error {
	data, err := s.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

func RateKey(ip, username string) string {
	return fmt.Sprintf("%s:%s", ip, username)
}

const OpStepUpTTL = 30 * time.Minute
const OpStepUpPendingTTL = 70 * time.Second

func opStepUpKey(id uuid.UUID) string        { return "stepup-op:" + id.String() }
func opStepUpPendingKey(id uuid.UUID) string { return "stepup-pending:" + id.String() }

func (s *Store) PutOpStepUp(ctx context.Context, sessionID, userID uuid.UUID) error {
	if s == nil || sessionID == uuid.Nil {
		return fmt.Errorf("invalid session")
	}
	return s.PutJSON(ctx, opStepUpKey(sessionID), StepUpGrant{UserID: userID, SessionID: sessionID}, OpStepUpTTL)
}

func (s *Store) HasOpStepUp(ctx context.Context, sessionID, userID uuid.UUID) bool {
	if s == nil || sessionID == uuid.Nil {
		return false
	}
	var g StepUpGrant
	if err := s.GetJSON(ctx, opStepUpKey(sessionID), &g); err != nil {
		return false
	}
	return g.UserID == userID
}

func (s *Store) ClearOpStepUp(ctx context.Context, sessionID uuid.UUID) {
	if s == nil || sessionID == uuid.Nil {
		return
	}
	_ = s.DeleteKey(ctx, opStepUpKey(sessionID))
	_ = s.DeleteKey(ctx, opStepUpPendingKey(sessionID))
}

func (s *Store) PutOpStepUpPending(ctx context.Context, sessionID uuid.UUID, p OpStepUpPending) error {
	if s == nil || sessionID == uuid.Nil {
		return fmt.Errorf("invalid session")
	}
	return s.PutJSON(ctx, opStepUpPendingKey(sessionID), p, OpStepUpPendingTTL)
}

func (s *Store) GetOpStepUpPending(ctx context.Context, sessionID uuid.UUID) (OpStepUpPending, bool) {
	var p OpStepUpPending
	if s == nil || sessionID == uuid.Nil {
		return p, false
	}
	if err := s.GetJSON(ctx, opStepUpPendingKey(sessionID), &p); err != nil {
		return p, false
	}
	return p, p.ChallengeToken != ""
}

func (s *Store) ClearOpStepUpPending(ctx context.Context, sessionID uuid.UUID) {
	if s == nil || sessionID == uuid.Nil {
		return
	}
	_ = s.DeleteKey(ctx, opStepUpPendingKey(sessionID))
}
