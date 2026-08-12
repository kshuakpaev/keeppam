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
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
}

type Challenge struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
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

func RateKey(ip, username string) string {
	return fmt.Sprintf("%s:%s", ip, username)
}
