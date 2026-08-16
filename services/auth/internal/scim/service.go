package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/audit"
	"github.com/keeppam/auth/internal/crypto"
	"github.com/keeppam/auth/internal/store"
	"github.com/keeppam/auth/internal/users"
)

type Service struct {
	db    *store.DB
	users *users.Service
	aud   *audit.Service
}

func New(db *store.DB, usersSvc *users.Service, aud *audit.Service) *Service {
	return &Service{db: db, users: usersSvc, aud: aud}
}

func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (UserResource, error) {
	u, err := s.users.Get(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return UserResource{}, errNotFound("user")
		}
		return UserResource{}, err
	}
	return s.toUser(ctx, u), nil
}

func (s *Service) ListUsers(ctx context.Context, filter string, startIndex, count int) (ListResponse, error) {
	off, lim := ClampPage(startIndex, count)
	if filter != "" {
		eq, ok := ParseEqFilter(filter)
		if !ok {
			return ListResponse{}, errFilter()
		}
		var u store.User
		var err error
		switch eq.Attr {
		case "username":
			u, err = s.db.GetUserByUsername(ctx, eq.Value)
		case "externalid":
			id, e := s.lookupAlias(ctx, "user", eq.Value)
			if e != nil {
				return emptyList(startIndex, lim), nil
			}
			u, err = s.db.GetUserByID(ctx, id)
		default:
			return ListResponse{}, errFilter()
		}
		if err != nil {
			return emptyList(startIndex, lim), nil
		}
		res := s.toUser(ctx, u)
		return ListResponse{
			Schemas: []string{schemaList}, TotalResults: 1, StartIndex: 1, ItemsPerPage: 1, Resources: []any{res},
		}, nil
	}
	list, err := s.db.ListUsers(ctx)
	if err != nil {
		return ListResponse{}, err
	}
	total := len(list)
	if off > total {
		off = total
	}
	end := off + lim
	if end > total {
		end = total
	}
	page := list[off:end]
	out := make([]any, 0, len(page))
	for _, u := range page {
		out = append(out, s.toUser(ctx, u))
	}
	si := off + 1
	if total == 0 {
		si = 1
	}
	return ListResponse{
		Schemas: []string{schemaList}, TotalResults: total, StartIndex: si, ItemsPerPage: len(out), Resources: out,
	}, nil
}

func (s *Service) CreateUser(ctx context.Context, in UserResource, defaultRole, ip string) (UserResource, error) {
	username := strings.ToLower(strings.TrimSpace(in.UserName))
	email := primaryEmail(in)
	if username == "" || email == "" {
		return UserResource{}, errBad("userName and emails.value required")
	}
	if _, err := s.db.GetUserByUsername(ctx, username); err == nil {
		return UserResource{}, errConflict("userName already exists")
	}
	role := strings.TrimSpace(defaultRole)
	if role == "" || strings.EqualFold(role, "admin") {
		role = "operator"
	}
	hash, err := crypto.HashPassword(uuid.NewString() + uuid.NewString())
	if err != nil {
		return UserResource{}, err
	}
	now := time.Now().UTC()
	u := store.User{
		ID: store.NewID(), Username: username, Email: email, DisplayName: displayNameOf(in),
		PasswordHash: hash, Status: "active", AuthSource: "scim", CreatedAt: now, UpdatedAt: now,
	}
	created, err := s.db.CreateUser(ctx, u, []string{role})
	if err != nil {
		return UserResource{}, asError(err)
	}
	if err := s.saveAlias(ctx, "user", created.ID, in.ExternalID); err != nil {
		return UserResource{}, asError(err)
	}
	_ = s.aud.Record(ctx, nil, "scim.user.created", "user", created.ID.String(), ip, "scim", map[string]any{"username": username})
	if in.Active != nil && !*in.Active {
		if err := s.setActive(ctx, created, false, ip); err != nil {
			return UserResource{}, err
		}
		created.Status = "disabled"
	}
	return s.toUser(ctx, created), nil
}

func (s *Service) PutUser(ctx context.Context, id uuid.UUID, in UserResource, ip string) (UserResource, error) {
	u, err := s.users.Get(ctx, id)
	if err != nil {
		return UserResource{}, errNotFound("user")
	}
	if in.UserName != "" {
		u.Username = strings.ToLower(strings.TrimSpace(in.UserName))
	}
	if em := primaryEmail(in); em != "" {
		u.Email = em
	}
	if dn := displayNameOf(in); dn != "" {
		u.DisplayName = dn
	}
	if in.Active != nil {
		if !*in.Active {
			if err := s.guardDisable(ctx, u); err != nil {
				return UserResource{}, err
			}
			u.Status = "disabled"
		} else {
			u.Status = "active"
			u.LockedUntil = nil
			u.FailedLoginCount = 0
		}
	}
	u.UpdatedAt = time.Now().UTC()
	updated, err := s.db.UpdateUser(ctx, u, nil)
	if err != nil {
		return UserResource{}, asError(err)
	}
	if err := s.saveAlias(ctx, "user", id, in.ExternalID); err != nil {
		return UserResource{}, asError(err)
	}
	_ = s.aud.Record(ctx, nil, "scim.user.updated", "user", id.String(), ip, "scim", nil)
	return s.toUser(ctx, updated), nil
}

func (s *Service) PatchUser(ctx context.Context, id uuid.UUID, ops []PatchOperation, ip string) (UserResource, error) {
	u, err := s.users.Get(ctx, id)
	if err != nil {
		return UserResource{}, errNotFound("user")
	}
	cur := s.toUser(ctx, u)
	if err := applyUserPatch(&cur, ops); err != nil {
		return UserResource{}, err
	}
	return s.PutUser(ctx, id, cur, ip)
}

func (s *Service) DeleteUser(ctx context.Context, id uuid.UUID, ip string) error {
	u, err := s.users.Get(ctx, id)
	if err != nil {
		return errNotFound("user")
	}
	if err := s.setActive(ctx, u, false, ip); err != nil {
		return err
	}
	_ = s.aud.Record(ctx, nil, "scim.user.disabled", "user", id.String(), ip, "scim", nil)
	return nil
}

func (s *Service) GetGroup(ctx context.Context, id uuid.UUID) (GroupResource, error) {
	g, err := s.users.GetGroup(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return GroupResource{}, errNotFound("group")
		}
		return GroupResource{}, err
	}
	return s.toGroup(ctx, g), nil
}

func (s *Service) ListGroups(ctx context.Context, filter string, startIndex, count int) (ListResponse, error) {
	off, lim := ClampPage(startIndex, count)
	if filter != "" {
		eq, ok := ParseEqFilter(filter)
		if !ok {
			return ListResponse{}, errFilter()
		}
		var g users.Group
		var err error
		switch eq.Attr {
		case "displayname":
			g, err = s.users.FindGroupByName(ctx, eq.Value)
		case "externalid":
			id, e := s.lookupAlias(ctx, "group", eq.Value)
			if e != nil {
				return emptyList(startIndex, lim), nil
			}
			g, err = s.users.GetGroup(ctx, id)
		default:
			return ListResponse{}, errFilter()
		}
		if err != nil {
			return emptyList(startIndex, lim), nil
		}
		res := s.toGroup(ctx, g)
		return ListResponse{
			Schemas: []string{schemaList}, TotalResults: 1, StartIndex: 1, ItemsPerPage: 1, Resources: []any{res},
		}, nil
	}
	list, err := s.users.ListGroups(ctx)
	if err != nil {
		return ListResponse{}, err
	}
	total := len(list)
	if off > total {
		off = total
	}
	end := off + lim
	if end > total {
		end = total
	}
	out := make([]any, 0, end-off)
	for _, g := range list[off:end] {
		full, err := s.users.GetGroup(ctx, g.ID)
		if err != nil {
			continue
		}
		out = append(out, s.toGroup(ctx, full))
	}
	si := off + 1
	if total == 0 {
		si = 1
	}
	return ListResponse{
		Schemas: []string{schemaList}, TotalResults: total, StartIndex: si, ItemsPerPage: len(out), Resources: out,
	}, nil
}

func (s *Service) CreateGroup(ctx context.Context, in GroupResource, ip string) (GroupResource, error) {
	name := strings.ToLower(strings.TrimSpace(in.DisplayName))
	if name == "" {
		return GroupResource{}, errBad("displayName required")
	}
	if _, err := s.users.FindGroupByName(ctx, name); err == nil {
		return GroupResource{}, errConflict("displayName already exists")
	}
	g, err := s.users.CreateGroup(ctx, uuid.Nil, users.GroupInput{Name: name, Description: "scim"}, ip, "scim")
	if err != nil {
		return GroupResource{}, asError(err)
	}
	if err := s.saveAlias(ctx, "group", g.ID, in.ExternalID); err != nil {
		return GroupResource{}, asError(err)
	}
	if len(in.Members) > 0 {
		if err := s.users.ReplaceMembers(ctx, g.ID, memberIDs(in.Members)); err != nil {
			return GroupResource{}, asError(err)
		}
		g, _ = s.users.GetGroup(ctx, g.ID)
	}
	_ = s.aud.Record(ctx, nil, "scim.group.created", "group", g.ID.String(), ip, "scim", map[string]any{"name": name})
	return s.toGroup(ctx, g), nil
}

func (s *Service) PutGroup(ctx context.Context, id uuid.UUID, in GroupResource, ip string) (GroupResource, error) {
	g, err := s.users.GetGroup(ctx, id)
	if err != nil {
		return GroupResource{}, errNotFound("group")
	}
	name := strings.ToLower(strings.TrimSpace(in.DisplayName))
	if name == "" {
		name = g.Name
	}
	parent := ""
	if g.ParentID != nil {
		parent = g.ParentID.String()
	}
	g, err = s.users.UpdateGroup(ctx, uuid.Nil, id, users.GroupInput{Name: name, Description: g.Description, ParentID: &parent}, ip, "scim")
	if err != nil {
		return GroupResource{}, asError(err)
	}
	if in.Members != nil {
		if err := s.users.ReplaceMembers(ctx, id, memberIDs(in.Members)); err != nil {
			return GroupResource{}, asError(err)
		}
	}
	if err := s.saveAlias(ctx, "group", id, in.ExternalID); err != nil {
		return GroupResource{}, asError(err)
	}
	g, _ = s.users.GetGroup(ctx, id)
	_ = s.aud.Record(ctx, nil, "scim.group.updated", "group", id.String(), ip, "scim", nil)
	return s.toGroup(ctx, g), nil
}

func (s *Service) PatchGroup(ctx context.Context, id uuid.UUID, ops []PatchOperation, ip string) (GroupResource, error) {
	g, err := s.users.GetGroup(ctx, id)
	if err != nil {
		return GroupResource{}, errNotFound("group")
	}
	cur := s.toGroup(ctx, g)
	replaceAll, add, remove, display, err := classifyGroupPatch(ops)
	if err != nil {
		return GroupResource{}, err
	}
	if display != "" {
		cur.DisplayName = display
	}
	if replaceAll != nil {
		cur.Members = replaceAll
	} else {
		if len(add) > 0 {
			have := map[string]struct{}{}
			for _, m := range cur.Members {
				have[m.Value] = struct{}{}
			}
			for _, m := range add {
				if _, ok := have[m.Value]; !ok {
					cur.Members = append(cur.Members, m)
				}
			}
		}
		if len(remove) > 0 {
			drop := map[string]struct{}{}
			for _, m := range remove {
				drop[m.Value] = struct{}{}
			}
			var keep []Member
			for _, m := range cur.Members {
				if _, ok := drop[m.Value]; !ok {
					keep = append(keep, m)
				}
			}
			if keep == nil {
				keep = []Member{}
			}
			cur.Members = keep
		}
	}
	return s.PutGroup(ctx, id, cur, ip)
}

func (s *Service) DeleteGroup(ctx context.Context, id uuid.UUID, ip string) error {
	if err := s.users.DeleteGroup(ctx, uuid.Nil, id, ip, "scim"); err != nil {
		if err == pgx.ErrNoRows {
			return errNotFound("group")
		}
		return err
	}
	_, _ = s.db.Pool.Exec(ctx, `DELETE FROM scim_aliases WHERE kind='group' AND keeppam_id=$1`, id)
	return nil
}

func (s *Service) guardDisable(ctx context.Context, u store.User) error {
	if !hasAdmin(u) || u.Status != "active" {
		return nil
	}
	n, err := s.db.CountActiveAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return errForbidden("cannot disable the last active admin")
	}
	return nil
}

func (s *Service) setActive(ctx context.Context, u store.User, active bool, _ string) error {
	if !active {
		if err := s.guardDisable(ctx, u); err != nil {
			return err
		}
		u.Status = "disabled"
	} else {
		u.Status = "active"
		u.LockedUntil = nil
		u.FailedLoginCount = 0
	}
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.UpdateUser(ctx, u, nil)
	return err
}

func (s *Service) toUser(ctx context.Context, u store.User) UserResource {
	ext, _ := s.aliasOf(ctx, "user", u.ID)
	dn := u.DisplayName
	if dn == "" {
		dn = u.Username
	}
	return UserResource{
		Schemas: []string{schemaUser}, ID: u.ID.String(), ExternalID: ext, UserName: u.Username,
		Name: &Name{Formatted: dn}, DisplayName: dn,
		Emails: []Email{{Value: u.Email, Primary: true, Type: "work"}},
		Active: boolPtr(u.Status == "active"),
		Meta:   meta("User", u.ID.String(), u.CreatedAt, u.UpdatedAt),
	}
}

func (s *Service) toGroup(ctx context.Context, g users.Group) GroupResource {
	ext, _ := s.aliasOf(ctx, "group", g.ID)
	var members []Member
	for _, m := range g.Members {
		members = append(members, Member{Value: m.ID.String(), Type: "User"})
	}
	if members == nil {
		members = []Member{}
	}
	return GroupResource{
		Schemas: []string{schemaGroup}, ID: g.ID.String(), ExternalID: ext, DisplayName: g.Name,
		Members: members, Meta: meta("Group", g.ID.String(), g.CreatedAt, g.UpdatedAt),
	}
}

func (s *Service) saveAlias(ctx context.Context, kind string, id uuid.UUID, external string) error {
	external = strings.TrimSpace(external)
	if external == "" {
		return nil
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO scim_aliases (kind, keeppam_id, external_id) VALUES ($1,$2,$3)
		ON CONFLICT (kind, keeppam_id) DO UPDATE SET external_id=EXCLUDED.external_id`, kind, id, external)
	return err
}

func (s *Service) aliasOf(ctx context.Context, kind string, id uuid.UUID) (string, error) {
	var v string
	err := s.db.Pool.QueryRow(ctx, `SELECT external_id FROM scim_aliases WHERE kind=$1 AND keeppam_id=$2`, kind, id).Scan(&v)
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s *Service) lookupAlias(ctx context.Context, kind, external string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.db.Pool.QueryRow(ctx, `SELECT keeppam_id FROM scim_aliases WHERE kind=$1 AND external_id=$2`, kind, strings.TrimSpace(external)).Scan(&id)
	return id, err
}

func emptyList(start, lim int) ListResponse {
	if start < 1 {
		start = 1
	}
	return ListResponse{Schemas: []string{schemaList}, TotalResults: 0, StartIndex: start, ItemsPerPage: 0, Resources: []any{}}
}

func primaryEmail(in UserResource) string {
	for _, e := range in.Emails {
		if e.Primary && strings.TrimSpace(e.Value) != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	if len(in.Emails) > 0 {
		return strings.TrimSpace(in.Emails[0].Value)
	}
	return ""
}

func displayNameOf(in UserResource) string {
	if strings.TrimSpace(in.DisplayName) != "" {
		return strings.TrimSpace(in.DisplayName)
	}
	if in.Name != nil && strings.TrimSpace(in.Name.Formatted) != "" {
		return strings.TrimSpace(in.Name.Formatted)
	}
	return strings.TrimSpace(in.UserName)
}

func memberIDs(ms []Member) []string {
	var out []string
	for _, m := range ms {
		if strings.TrimSpace(m.Value) != "" {
			out = append(out, strings.TrimSpace(m.Value))
		}
	}
	return out
}

func hasAdmin(u store.User) bool {
	for _, r := range u.Roles {
		if r == "admin" {
			return true
		}
	}
	return false
}

func boolPtr(v bool) *bool { return &v }

func applyUserPatch(cur *UserResource, ops []PatchOperation) error {
	for _, op := range ops {
		kind := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.ToLower(strings.TrimSpace(op.Path))
		switch kind {
		case "add", "replace":
			switch path {
			case "", "displayname":
				if path == "displayname" {
					cur.DisplayName = stringify(op.Value)
				} else if m, ok := asMap(op.Value); ok {
					mergeUserMap(cur, m)
				}
			case "username":
				cur.UserName = stringify(op.Value)
			case "active":
				v := asBool(op.Value)
				cur.Active = &v
			case "name.formatted":
				if cur.Name == nil {
					cur.Name = &Name{}
				}
				cur.Name.Formatted = stringify(op.Value)
			case "emails":
				cur.Emails = asEmails(op.Value)
			default:
				if strings.HasPrefix(path, "emails") {
					cur.Emails = asEmails(op.Value)
				}
			}
		case "remove":
			if path == "active" {
				v := false
				cur.Active = &v
			}
		default:
			return errBad("unsupported patch op")
		}
	}
	return nil
}

func classifyGroupPatch(ops []PatchOperation) (replace []Member, add []Member, remove []Member, display string, err error) {
	for _, op := range ops {
		kind := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.ToLower(strings.TrimSpace(op.Path))
		switch kind {
		case "replace":
			if path == "displayname" || path == "" {
				if path == "displayname" {
					display = stringify(op.Value)
				} else if m, ok := asMap(op.Value); ok {
					if v, ok := m["displayName"].(string); ok {
						display = v
					}
					if _, ok := m["members"]; ok {
						replace = asMembers(m["members"])
					}
				}
			}
			if path == "members" {
				replace = asMembers(op.Value)
			}
		case "add":
			if strings.HasPrefix(path, "members") || path == "" {
				add = append(add, asMembers(op.Value)...)
			}
			if path == "displayname" {
				display = stringify(op.Value)
			}
		case "remove":
			if strings.HasPrefix(path, "members") {
				id := memberIDFromPath(op.Path)
				if id == "" {
					remove = append(remove, asMembers(op.Value)...)
				} else {
					remove = append(remove, Member{Value: id})
				}
			}
		default:
			err = errBad("unsupported patch op")
			return
		}
	}
	return
}

func memberIDFromPath(path string) string {
	// members[value eq "uuid"]
	low := strings.ToLower(path)
	i := strings.Index(low, "value eq")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(path[i+8:])
	rest = strings.Trim(rest, ` "]`)
	return rest
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		b, _ := json.Marshal(v)
		return strings.Trim(string(b), `"`)
	}
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "True"
	default:
		return false
	}
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func mergeUserMap(cur *UserResource, m map[string]any) {
	if v, ok := m["userName"].(string); ok {
		cur.UserName = v
	}
	if v, ok := m["displayName"].(string); ok {
		cur.DisplayName = v
	}
	if v, ok := m["active"].(bool); ok {
		cur.Active = &v
	}
	if v, ok := m["emails"]; ok {
		cur.Emails = asEmails(v)
	}
}

func asEmails(v any) []Email {
	b, _ := json.Marshal(v)
	var out []Email
	if json.Unmarshal(b, &out) == nil && len(out) > 0 {
		return out
	}
	var one Email
	if json.Unmarshal(b, &one) == nil && one.Value != "" {
		return []Email{one}
	}
	return nil
}

func asMembers(v any) []Member {
	b, _ := json.Marshal(v)
	var out []Member
	if json.Unmarshal(b, &out) == nil {
		if out == nil {
			return []Member{}
		}
		return out
	}
	var one Member
	if json.Unmarshal(b, &one) == nil && one.Value != "" {
		return []Member{one}
	}
	return nil
}
