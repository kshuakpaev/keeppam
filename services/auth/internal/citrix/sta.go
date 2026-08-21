package citrix

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

const staKeyPrefix = "citrix:sta:"

// STATicket is a KeepPAM-issued Secure Ticket Authority style ticket (SOW slice 1 stub).
// Real Citrix STA CGI is not emulated end-to-end; tickets are validated via KeepPAM API
// and embedded in .ica for audit / future HDX broker.
type STATicket struct {
	Ticket    string    `json:"ticket"`
	SessionID uuid.UUID `json:"session_id"`
	AssetID   uuid.UUID `json:"asset_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueSTATicket stores a random ticket bound to session/asset for TTL.
func IssueSTATicket(ctx context.Context, rdb *redis.Client, sessionID, assetID uuid.UUID, ttl time.Duration) (STATicket, error) {
	if rdb == nil {
		return STATicket{}, fmt.Errorf("redis required")
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return STATicket{}, err
	}
	ticket := strings.ToUpper(hex.EncodeToString(buf[:]))
	val := sessionID.String() + "|" + assetID.String()
	if err := rdb.Set(ctx, staKeyPrefix+ticket, val, ttl).Err(); err != nil {
		return STATicket{}, err
	}
	return STATicket{
		Ticket:    ticket,
		SessionID: sessionID,
		AssetID:   assetID,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}, nil
}

// ValidateSTATicket returns session and asset IDs if the ticket is still in Redis.
func ValidateSTATicket(ctx context.Context, rdb *redis.Client, ticket string) (sessionID, assetID uuid.UUID, err error) {
	ticket = strings.TrimSpace(strings.ToUpper(ticket))
	if ticket == "" || rdb == nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid ticket")
	}
	val, err := rdb.Get(ctx, staKeyPrefix+ticket).Result()
	if err == redis.Nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("ticket not found or expired")
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	parts := strings.SplitN(val, "|", 2)
	if len(parts) != 2 {
		return uuid.Nil, uuid.Nil, fmt.Errorf("corrupt ticket")
	}
	sessionID, err = uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	assetID, err = uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return sessionID, assetID, nil
}
