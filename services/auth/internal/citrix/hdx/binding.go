package hdx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	bindKeyPrefix  = "citrix:hdx:bind:"  // session → plugin_id|token
	tokenKeyPrefix = "citrix:hdx:token:" // ingest token → session
	seqKeyPrefix   = "citrix:hdx:seq:"   // session → last applied seq
)

// Binding links KeepPAM session ↔ OEM plugin session for recording ingest.
type Binding struct {
	SessionID       uuid.UUID
	PluginSessionID string
	IngestToken     string
}

func Bind(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, pluginSessionID string, ttl time.Duration) (Binding, error) {
	if rdb == nil {
		return Binding{}, fmt.Errorf("redis required")
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	tok, err := randomToken(24)
	if err != nil {
		return Binding{}, err
	}
	if pluginSessionID == "" {
		pluginSessionID = "pending"
	}
	b := Binding{SessionID: sessionID, PluginSessionID: pluginSessionID, IngestToken: tok}
	val := pluginSessionID + "|" + tok
	pipe := rdb.Pipeline()
	pipe.Set(ctx, bindKeyPrefix+sessionID.String(), val, ttl)
	pipe.Set(ctx, tokenKeyPrefix+tok, sessionID.String(), ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return Binding{}, err
	}
	return b, nil
}

// SetPluginSessionID updates the plugin id while keeping the ingest token.
func SetPluginSessionID(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, pluginSessionID string, ttl time.Duration) error {
	b, err := GetBinding(ctx, rdb, sessionID)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	val := pluginSessionID + "|" + b.IngestToken
	return rdb.Set(ctx, bindKeyPrefix+sessionID.String(), val, ttl).Err()
}

func GetBinding(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID) (Binding, error) {
	if rdb == nil {
		return Binding{}, fmt.Errorf("redis required")
	}
	val, err := rdb.Get(ctx, bindKeyPrefix+sessionID.String()).Result()
	if err == redis.Nil {
		return Binding{}, fmt.Errorf("no hdx binding")
	}
	if err != nil {
		return Binding{}, err
	}
	parts := strings.SplitN(val, "|", 2)
	if len(parts) != 2 {
		return Binding{}, fmt.Errorf("corrupt binding")
	}
	return Binding{SessionID: sessionID, PluginSessionID: parts[0], IngestToken: parts[1]}, nil
}

func LookupByToken(ctx context.Context, rdb *redis.Client, token string) (uuid.UUID, error) {
	token = strings.TrimSpace(token)
	if rdb == nil || token == "" {
		return uuid.Nil, fmt.Errorf("invalid token")
	}
	val, err := rdb.Get(ctx, tokenKeyPrefix+token).Result()
	if err == redis.Nil {
		return uuid.Nil, fmt.Errorf("token not found")
	}
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(val)
}

func ClearBinding(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID) {
	if rdb == nil {
		return
	}
	b, err := GetBinding(ctx, rdb, sessionID)
	_ = rdb.Del(ctx, bindKeyPrefix+sessionID.String(), seqKeyPrefix+sessionID.String()).Err()
	if err == nil && b.IngestToken != "" {
		_ = rdb.Del(ctx, tokenKeyPrefix+b.IngestToken).Err()
	}
}

func LastSeq(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID) int {
	if rdb == nil {
		return 0
	}
	n, err := rdb.Get(ctx, seqKeyPrefix+sessionID.String()).Int()
	if err != nil {
		return 0
	}
	return n
}

func SetLastSeq(ctx context.Context, rdb *redis.Client, sessionID uuid.UUID, seq int, ttl time.Duration) {
	if rdb == nil || seq <= 0 {
		return
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	_ = rdb.Set(ctx, seqKeyPrefix+sessionID.String(), strconv.Itoa(seq), ttl).Err()
}

// AppendJSONL writes one recording event to the Citrix session JSONL path.
func AppendJSONL(path string, ev RecordingEvt) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	row := map[string]any{"t": ev.T, "event": ev.Event}
	if ev.Seq > 0 {
		row["seq"] = ev.Seq
	}
	if len(ev.Meta) > 0 {
		row["meta"] = ev.Meta
	}
	return json.NewEncoder(f).Encode(row)
}

func NormalizeEvt(ev RecordingEvt) RecordingEvt {
	if ev.T == "" {
		ev.T = time.Now().UTC().Format(time.RFC3339Nano)
	}
	ev.Event = strings.TrimSpace(strings.ToLower(ev.Event))
	return ev
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CallbackURL builds the plugin → KeepPAM ingest URL.
func CallbackURL(publicBase string) string {
	base := strings.TrimRight(strings.TrimSpace(publicBase), "/")
	if base == "" {
		return ""
	}
	return base + "/api/v1/citrix/hdx/ingest"
}
