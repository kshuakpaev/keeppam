package policy

import (
	"context"

	"github.com/google/uuid"
)

// Snapshot is the ACL/Policy freeze taken at session connect.
// In-session JEA/risk use this instead of a live Evaluate.
type Snapshot struct {
	BindingID             *uuid.UUID   `json:"binding_id,omitempty"`
	GroupID               *uuid.UUID   `json:"group_id,omitempty"`
	AccessPolicyID        *uuid.UUID   `json:"access_policy_id,omitempty"`
	AccessPolicyName      string       `json:"access_policy_name,omitempty"`
	MaxRisk               int          `json:"max_risk"`
	RiskAction            string       `json:"risk_action,omitempty"`
	CommandPolicyPackID   *uuid.UUID   `json:"command_policy_pack_id,omitempty"`
	CommandPolicyPackName string       `json:"command_policy_pack_name,omitempty"`
	SQLPolicyPackID       *uuid.UUID   `json:"sql_policy_pack_id,omitempty"`
	SQLPolicyPackName     string       `json:"sql_policy_pack_name,omitempty"`
	HTTPPolicyPackID      *uuid.UUID   `json:"http_policy_pack_id,omitempty"`
	HTTPPolicyPackName    string       `json:"http_policy_pack_name,omitempty"`
	AppObjectPackID       *uuid.UUID   `json:"app_object_pack_id,omitempty"`
	AppObjectPackName     string       `json:"app_object_pack_name,omitempty"`
	AllowedNamespaces     []string     `json:"allowed_namespaces,omitempty"`
	AllowedEgress         []string     `json:"allowed_egress,omitempty"`
	TagACL                bool         `json:"tag_acl,omitempty"`
	MatchTags             []string     `json:"match_tags,omitempty"`
	MatchMode             string       `json:"match_mode,omitempty"`
	BreakGlass            bool         `json:"break_glass,omitempty"`
	AdminBypass           bool         `json:"admin_bypass,omitempty"`
	PIIAction             string       `json:"pii_action,omitempty"`
	FileTransfer          string       `json:"file_transfer,omitempty"`
	OCRLang               string       `json:"ocr_lang,omitempty"`
	OCRIntervalSec        int          `json:"ocr_interval_sec,omitempty"`
	OCRMaxFrames          int          `json:"ocr_max_frames,omitempty"`
	RDPClipboard          bool         `json:"rdp_clipboard,omitempty"`
	RDPDrive              bool         `json:"rdp_drive,omitempty"`
	RDPPrinter            bool         `json:"rdp_printer,omitempty"`
	RDPNative             bool         `json:"rdp_native,omitempty"`
	TerminalCharset       string       `json:"terminal_charset,omitempty"`
	DlpPatterns           []DlpPattern `json:"dlp_patterns,omitempty"`
}

func FromResult(ev AccessResult) Snapshot {
	ns := ev.AllowedNamespaces
	if ns == nil {
		ns = []string{}
	}
	eg := ev.AllowedEgress
	if eg == nil {
		eg = []string{}
	}
	tags := ev.MatchTags
	if tags == nil {
		tags = []string{}
	}
	return Snapshot{
		BindingID:           ev.BindingID,
		GroupID:             ev.GroupID,
		AccessPolicyID:      ev.AccessPolicyID,
		MaxRisk:             ev.MaxRisk,
		RiskAction:          ev.RiskAction,
		CommandPolicyPackID: ev.CommandPolicyPackID,
		SQLPolicyPackID:     ev.SQLPolicyPackID,
		HTTPPolicyPackID:    ev.HTTPPolicyPackID,
		AppObjectPackID:     ev.AppObjectPackID,
		AllowedNamespaces:   ns,
		AllowedEgress:       eg,
		TagACL:              ev.TagACL,
		MatchTags:           tags,
		MatchMode:           ev.MatchMode,
		PIIAction:           ev.PIIAction,
		FileTransfer:        ev.FileTransfer,
	}
}

func (sn *Snapshot) EffectiveContentDLP() ContentDLP {
	return sn.ContentDLP()
}

func (sn Snapshot) toResult() AccessResult {
	return AccessResult{
		OK:                  true,
		BindingID:           sn.BindingID,
		GroupID:             sn.GroupID,
		AccessPolicyID:      sn.AccessPolicyID,
		CommandPolicyPackID: sn.CommandPolicyPackID,
		SQLPolicyPackID:     sn.SQLPolicyPackID,
		HTTPPolicyPackID:    sn.HTTPPolicyPackID,
		AppObjectPackID:     sn.AppObjectPackID,
		AllowedNamespaces:   sn.AllowedNamespaces,
		AllowedEgress:       sn.AllowedEgress,
		MaxRisk:             sn.MaxRisk,
		RiskAction:          sn.RiskAction,
		TagACL:              sn.TagACL,
		MatchTags:           sn.MatchTags,
		MatchMode:           sn.MatchMode,
		PIIAction:           sn.PIIAction,
		FileTransfer:        sn.FileTransfer,
	}
}

func (s *Service) Freeze(ctx context.Context, ev AccessResult, breakGlass, adminBypass bool) Snapshot {
	sn := FromResult(ev)
	sn.BreakGlass = breakGlass
	sn.AdminBypass = adminBypass
	s.EnrichSnapshot(ctx, &sn)
	return sn
}

func (sn *Snapshot) EffectiveFileTransfer() string {
	if sn == nil {
		return FileTransferDeny
	}
	return EffectiveFileTransfer(sn.FileTransfer)
}

func (s *Service) EnrichSnapshot(ctx context.Context, sn *Snapshot) {
	if s == nil || sn == nil || s.db == nil {
		return
	}
	if sn.AccessPolicyID != nil && sn.AccessPolicyName == "" {
		_ = s.db.Pool.QueryRow(ctx, `SELECT name FROM access_policies WHERE id=$1`, *sn.AccessPolicyID).Scan(&sn.AccessPolicyName)
	}
	if sn.CommandPolicyPackID != nil && sn.CommandPolicyPackName == "" {
		_ = s.db.Pool.QueryRow(ctx, `SELECT name FROM command_policy_packs WHERE id=$1`, *sn.CommandPolicyPackID).Scan(&sn.CommandPolicyPackName)
	}
	if sn.SQLPolicyPackID != nil && sn.SQLPolicyPackName == "" {
		_ = s.db.Pool.QueryRow(ctx, `SELECT name FROM sql_policy_packs WHERE id=$1`, *sn.SQLPolicyPackID).Scan(&sn.SQLPolicyPackName)
	}
	if sn.HTTPPolicyPackID != nil && sn.HTTPPolicyPackName == "" {
		_ = s.db.Pool.QueryRow(ctx, `SELECT name FROM http_policy_packs WHERE id=$1`, *sn.HTTPPolicyPackID).Scan(&sn.HTTPPolicyPackName)
	}
	if sn.AppObjectPackID != nil && sn.AppObjectPackName == "" {
		_ = s.db.Pool.QueryRow(ctx, `SELECT name FROM app_object_packs WHERE id=$1`, *sn.AppObjectPackID).Scan(&sn.AppObjectPackName)
	}
	s.loadDlpPatternsForSnapshot(ctx, sn)
	s.loadOCRForSnapshot(ctx, sn)
	s.loadRDPForSnapshot(ctx, sn)
}

func (s *Service) loadRDPForSnapshot(ctx context.Context, sn *Snapshot) {
	if sn == nil || sn.AccessPolicyID == nil || s.db == nil {
		return
	}
	var clip, drive, printer, native bool
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(rdp_clipboard,false), COALESCE(rdp_drive,false),
		       COALESCE(rdp_printer,false), COALESCE(rdp_native,false)
		FROM access_policies WHERE id=$1`, *sn.AccessPolicyID).Scan(&clip, &drive, &printer, &native)
	if err != nil {
		return
	}
	sn.RDPClipboard = clip
	sn.RDPDrive = drive
	sn.RDPPrinter = printer
	sn.RDPNative = native
}

func (s *Service) loadOCRForSnapshot(ctx context.Context, sn *Snapshot) {
	if sn == nil {
		return
	}
	if sn.AccessPolicyID != nil && (sn.OCRLang == "" || sn.OCRIntervalSec == 0 || sn.OCRMaxFrames == 0) {
		var lang string
		var iv, n int
		err := s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(ocr_lang,''), COALESCE(ocr_interval_sec,0), COALESCE(ocr_max_frames,0)
			FROM access_policies WHERE id=$1`, *sn.AccessPolicyID).Scan(&lang, &iv, &n)
		if err == nil {
			if sn.OCRLang == "" {
				sn.OCRLang = lang
			}
			if sn.OCRIntervalSec == 0 {
				sn.OCRIntervalSec = iv
			}
			if sn.OCRMaxFrames == 0 {
				sn.OCRMaxFrames = n
			}
		}
	}
	opt := sn.OCR()
	sn.OCRLang, sn.OCRIntervalSec, sn.OCRMaxFrames = opt.Lang, opt.IntervalSec, opt.MaxFrames
}
