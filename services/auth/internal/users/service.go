package users

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
)

type Service struct {
	db    *store.DB
	audit *audit.Service
}

func New(db *store.DB, auditSvc *audit.Service) *Service {
	return &Service{db: db, audit: auditSvc}
}

type CreateInput struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
}

type UpdateInput struct {
	Email       *string   `json:"email"`
	DisplayName *string   `json:"display_name"`
	Status      *string   `json:"status"`
	Roles       *[]string `json:"roles"`
	Tags        *[]string `json:"tags"`
}

type CreateResult struct {
	User             store.User `json:"user"`
	TemporaryPassword string    `json:"temporary_password,omitempty"`
}

func (s *Service) List(ctx context.Context) ([]store.User, error) {
	return s.db.ListUsers(ctx)
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (store.User, error) {
	return s.db.GetUserByID(ctx, id)
}

func (s *Service) Create(ctx context.Context, actorID uuid.UUID, in CreateInput, ip, ua string) (CreateResult, error) {
	if in.Username == "" || in.Email == "" {
		return CreateResult{}, fmt.Errorf("username and email required")
	}
	password := in.Password
	temp := ""
	if password == "" {
		var err error
		password, err = crypto.RandomPassword(16)
		if err != nil {
			return CreateResult{}, err
		}
		temp = password
	}
	if len(password) < 10 {
		return CreateResult{}, fmt.Errorf("password too short")
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return CreateResult{}, err
	}
	roles := in.Roles
	if len(roles) == 0 {
		roles = []string{"operator"}
	}
	now := time.Now().UTC()
	u := store.User{
		ID:                 store.NewID(),
		Username:           in.Username,
		Email:              in.Email,
		DisplayName:        in.DisplayName,
		PasswordHash:       hash,
		Status:             "active",
		AuthSource:         "local",
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedBy:          &actorID,
	}
	created, err := s.db.CreateUser(ctx, u, roles)
	if err != nil {
		return CreateResult{}, err
	}
	_ = s.audit.Record(ctx, &actorID, "user.created", "user", created.ID.String(), ip, ua, map[string]any{
		"username": created.Username,
		"roles":    roles,
	})
	_ = s.audit.Record(ctx, &actorID, "role.assigned", "user", created.ID.String(), ip, ua, map[string]any{"roles": roles})
	return CreateResult{User: created, TemporaryPassword: temp}, nil
}

func (s *Service) Update(ctx context.Context, actorID, id uuid.UUID, in UpdateInput, ip, ua string) (store.User, error) {
	u, err := s.db.GetUserByID(ctx, id)
	if err != nil {
		return store.User{}, err
	}
	if in.Email != nil {
		u.Email = *in.Email
	}
	if in.DisplayName != nil {
		u.DisplayName = *in.DisplayName
	}
	if in.Status != nil {
		switch *in.Status {
		case "active", "disabled", "locked":
			u.Status = *in.Status
			if *in.Status == "active" {
				u.LockedUntil = nil
				u.FailedLoginCount = 0
			}
		default:
			return store.User{}, fmt.Errorf("invalid status")
		}
	}
	u.UpdatedAt = time.Now().UTC()
	updated, err := s.db.UpdateUser(ctx, u, in.Roles)
	if err != nil {
		return store.User{}, err
	}
	if in.Tags != nil {
		if err := s.db.SetUserTags(ctx, id, *in.Tags); err != nil {
			return store.User{}, err
		}
		_ = s.audit.Record(ctx, &actorID, "user.tags.updated", "user", id.String(), ip, ua, map[string]any{"tags": *in.Tags})
		updated, err = s.db.GetUserByID(ctx, id)
		if err != nil {
			return store.User{}, err
		}
	}
	action := "user.updated"
	if in.Status != nil && *in.Status == "disabled" {
		action = "user.disabled"
	}
	_ = s.audit.Record(ctx, &actorID, action, "user", id.String(), ip, ua, map[string]any{
		"status": updated.Status,
		"roles":  updated.Roles,
	})
	if in.Roles != nil {
		_ = s.audit.Record(ctx, &actorID, "role.assigned", "user", id.String(), ip, ua, map[string]any{"roles": *in.Roles})
	}
	return updated, nil
}

func (s *Service) ResetPassword(ctx context.Context, actorID, id uuid.UUID, ip, ua string) (string, error) {
	u, err := s.db.GetUserByID(ctx, id)
	if err != nil {
		return "", err
	}
	temp, err := crypto.RandomPassword(16)
	if err != nil {
		return "", err
	}
	hash, err := crypto.HashPassword(temp)
	if err != nil {
		return "", err
	}
	u.PasswordHash = hash
	u.MustChangePassword = true
	u.UpdatedAt = time.Now().UTC()
	_, err = s.db.UpdateUser(ctx, u, nil)
	if err != nil {
		return "", err
	}
	_ = s.audit.Record(ctx, &actorID, "user.password.reset", "user", id.String(), ip, ua, nil)
	return temp, nil
}

func (s *Service) ResetMFA(ctx context.Context, actorID, id uuid.UUID, ip, ua string) error {
	u, err := s.db.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	u.MFAEnabled = false
	u.MFASecretEnc = nil
	u.UpdatedAt = time.Now().UTC()
	_, err = s.db.UpdateUser(ctx, u, nil)
	if err != nil {
		return err
	}
	_ = s.db.DeleteWebAuthnCredentialsByUser(ctx, id)
	return s.audit.Record(ctx, &actorID, "user.mfa.reset", "user", id.String(), ip, ua, nil)
}

func (s *Service) ListRoles(ctx context.Context) ([]store.Role, error) {
	return s.db.ListRoles(ctx)
}

func IsNotFound(err error) bool {
	return err == pgx.ErrNoRows || (err != nil && err.Error() == "not found")
}
