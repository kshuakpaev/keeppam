package ai

import (
	"time"

	"github.com/google/uuid"
)

const (
	KindSessionSummary  = "session_summary"
	KindEmbedSession    = "embed_session"
	KindApprovalBrief   = "approval_brief"
	KindRiskExplain     = "risk_explain"
	KindComplianceProse = "compliance_prose"
	KindHelpAsk         = "help_ask"
	KindJEADraft        = "jea_draft"

	BriefJIT        = "jit"
	BriefSupervisor = "supervisor"
	BriefCommand    = "command"

	ModeOff      = "off"
	ModeOn       = "on"
	ModeExternal = "external"
)

type Settings struct {
	Mode          string     `json:"mode"`
	Endpoint      string     `json:"endpoint"`
	Model         string     `json:"model"`
	EmbedModel    string     `json:"embed_model"`
	MaxInputChars int        `json:"max_input_chars"`
	TimeoutS      int        `json:"timeout_s"`
	Lang          string     `json:"lang"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastError     string     `json:"last_error"`
	UpdatedAt     time.Time  `json:"updated_at"`
	AllowExternal bool       `json:"allow_external,omitempty"`
	Licensed      bool       `json:"licensed"`
}

type Bullet struct {
	Text     string     `json:"text"`
	EventID  *uuid.UUID `json:"event_id,omitempty"`
	Offset   *float64   `json:"offset,omitempty"`
	Kind     string     `json:"kind,omitempty"`
	Type     string     `json:"type,omitempty"`
}

type RiskNote struct {
	EventID *uuid.UUID `json:"event_id,omitempty"`
	Kind    string     `json:"kind"`
	Text    string     `json:"text"`
}

type OffsetRef struct {
	Label  string  `json:"label"`
	Offset float64 `json:"offset"`
}

type Summary struct {
	SessionID        uuid.UUID  `json:"session_id"`
	Status           string     `json:"status"`
	Model            string     `json:"model,omitempty"`
	Headline         string     `json:"headline"`
	Summary          string     `json:"summary"`
	ScreenNarrative  string     `json:"screen_narrative,omitempty"`
	Bullets          []Bullet   `json:"bullets"`
	RiskNotes        []RiskNote `json:"risk_notes"`
	Offsets          []OffsetRef `json:"offsets"`
	InputHash        string     `json:"input_hash,omitempty"`
	SkipReason       string     `json:"skip_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type RiskExplain struct {
	SessionID uuid.UUID `json:"session_id"`
	Status    string    `json:"status"`
	Model     string    `json:"model,omitempty"`
	Text      string    `json:"text"`
	Factors   []string  `json:"factors"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Brief struct {
	Kind      string         `json:"kind"`
	RefID     uuid.UUID      `json:"ref_id"`
	Status    string         `json:"status"`
	Model     string         `json:"model,omitempty"`
	Facts     map[string]any `json:"facts"`
	Brief     string         `json:"brief"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type Draft struct {
	Prompt   string            `json:"prompt"`
	Policy   map[string]any    `json:"policy"`
	Patterns []string          `json:"patterns"`
	Notes    []string          `json:"notes"`
	Model    string            `json:"model,omitempty"`
}

type HelpAnswer struct {
	Question string   `json:"question"`
	Answer   string   `json:"answer"`
	Topics   []string `json:"topics,omitempty"`
	Model    string   `json:"model,omitempty"`
}

type indexEvent struct {
	ID      uuid.UUID
	Type    string
	Payload map[string]any
	TS      time.Time
	Snippet string
	Offset  float64
}
