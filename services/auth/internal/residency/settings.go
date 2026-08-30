package residency

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/store"
)

type Settings struct {
	Region         string     `json:"region"`
	CountryName    string     `json:"country_name"`
	OnPrem         bool       `json:"on_prem"`
	AttestedAt     *time.Time `json:"attested_at,omitempty"`
	AttestedBy     *uuid.UUID `json:"attested_by,omitempty"`
	AttestedByName string     `json:"attested_by_name,omitempty"`
	Notes          string     `json:"notes"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Compliant      bool       `json:"compliant"`
	Risks          []string   `json:"risks,omitempty"`
}

type UpdateInput struct {
	Region string `json:"region"`
	OnPrem *bool  `json:"on_prem"`
	Notes  string `json:"notes"`
	Attest bool   `json:"attest"`
}

type Service struct {
	db  *store.DB
	aud *audit.Service
}

func New(db *store.DB, aud *audit.Service) *Service {
	return &Service{db: db, aud: aud}
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	var out Settings
	err := s.db.Pool.QueryRow(ctx, `
		SELECT r.region, r.country_name, r.on_prem, r.attested_at, r.attested_by,
			COALESCE(u.username, ''), COALESCE(r.notes, ''), r.updated_at
		FROM data_residency_settings r
		LEFT JOIN users u ON u.id = r.attested_by
		WHERE r.id = 1`).Scan(
		&out.Region, &out.CountryName, &out.OnPrem, &out.AttestedAt, &out.AttestedBy,
		&out.AttestedByName, &out.Notes, &out.UpdatedAt)
	if err != nil {
		return Settings{}, err
	}
	return out, nil
}

func (s *Service) Update(ctx context.Context, actor uuid.UUID, in UpdateInput, dataKeySource, s3Endpoint, ip, ua string) (Settings, error) {
	cur, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	region := strings.ToUpper(strings.TrimSpace(in.Region))
	if region == "" {
		region = cur.Region
	}
	if region == "" {
		region = RegionKZ
	}
	onPrem := cur.OnPrem
	if in.OnPrem != nil {
		onPrem = *in.OnPrem
	}
	notes := in.Notes
	country := CountryKZ
	if region != RegionKZ {
		country = region
	}
	if in.Attest {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE data_residency_settings SET
				region=$1, country_name=$2, on_prem=$3, notes=$4,
				attested_at=NOW(), attested_by=$5, updated_at=NOW()
			WHERE id=1`, region, country, onPrem, notes, actor)
	} else {
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE data_residency_settings SET
				region=$1, country_name=$2, on_prem=$3, notes=$4, updated_at=NOW()
			WHERE id=1`, region, country, onPrem, notes)
	}
	if err != nil {
		return Settings{}, err
	}
	out, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	out.AttachCompliance(dataKeySource, s3Endpoint)
	if s.aud != nil {
		_ = s.aud.Record(ctx, &actor, "settings.residency.updated", "data_residency", "1", ip, ua, map[string]any{
			"region": out.Region, "on_prem": out.OnPrem, "attest": in.Attest, "compliant": out.Compliant,
		})
	}
	return out, nil
}

func (s *Settings) AttachCompliance(dataKeySource, s3Endpoint string) {
	s.Compliant = Compliant(s.Region, s.OnPrem, dataKeySource, s3Endpoint)
	s.Risks = Risks(s.Region, s.OnPrem, dataKeySource, s3Endpoint)
	if s.Risks == nil {
		s.Risks = []string{}
	}
}
