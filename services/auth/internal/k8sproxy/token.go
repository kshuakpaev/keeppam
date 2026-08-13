package k8sproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const tokenPrefix = "keeppam:k8s:"

func IssueToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, ttl time.Duration) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return tok, rdb.Set(ctx, tokenPrefix+sessionID.String(), tok, ttl).Err()
}

func ClearToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID) {
	if rdb == nil {
		return
	}
	_ = rdb.Del(ctx, tokenPrefix+sessionID.String()).Err()
}

func GetToken(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID) (string, error) {
	return rdb.Get(ctx, tokenPrefix+sessionID.String()).Result()
}

func ParseBearer(raw string) (uuid.UUID, string, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "Bearer ")
	raw = strings.TrimPrefix(raw, "bearer ")
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return uuid.Nil, "", fmt.Errorf("invalid token")
	}
	id, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid token")
	}
	return id, parts[1], nil
}

func BearerValue(sessionID uuid.UUID, tok string) string {
	return sessionID.String() + "." + tok
}
