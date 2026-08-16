package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/scim"
)

type scimRoleCtx struct{}

func (s *Server) mountSCIM(r chi.Router) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(s.requireSCIM)
		r.Get("/", s.handleSCIMServiceProviderConfig)
		r.Get("/ServiceProviderConfig", s.handleSCIMServiceProviderConfig)
		r.Get("/Schemas", s.handleSCIMSchemas)
		r.Get("/ResourceTypes", s.handleSCIMResourceTypes)

		r.Get("/Users", s.handleSCIMListUsers)
		r.Post("/Users", s.handleSCIMCreateUser)
		r.Get("/Users/{id}", s.handleSCIMGetUser)
		r.Put("/Users/{id}", s.handleSCIMPutUser)
		r.Patch("/Users/{id}", s.handleSCIMPatchUser)
		r.Delete("/Users/{id}", s.handleSCIMDeleteUser)

		r.Get("/Groups", s.handleSCIMListGroups)
		r.Post("/Groups", s.handleSCIMCreateGroup)
		r.Get("/Groups/{id}", s.handleSCIMGetGroup)
		r.Put("/Groups/{id}", s.handleSCIMPutGroup)
		r.Patch("/Groups/{id}", s.handleSCIMPatchGroup)
		r.Delete("/Groups/{id}", s.handleSCIMDeleteGroup)
	})
}

func (s *Server) requireSCIM(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.scim == nil || s.settings == nil {
			scim.WriteErr(w, scim.ErrUnauthorized())
			return
		}
		rt, err := s.settings.SCIMRuntime(r.Context())
		if err != nil || !rt.Enabled || strings.TrimSpace(rt.Token) == "" {
			scim.WriteErr(w, scim.ErrUnauthorized())
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), []byte(rt.Token)) != 1 {
			scim.WriteErr(w, scim.ErrUnauthorized())
			return
		}
		ctx := context.WithValue(r.Context(), scimRoleCtx{}, rt.DefaultRole)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func scimDefaultRole(r *http.Request) string {
	v, _ := r.Context().Value(scimRoleCtx{}).(string)
	if v == "" {
		return "operator"
	}
	return v
}

func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	scim.Write(w, http.StatusOK, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]any{"supported": true},
		"bulk":    map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":  map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Bearer token from KeepPAM SCIM settings",
			"specUri":     "https://www.rfc-editor.org/rfc/rfc6750",
			"primary":     true,
		}},
	})
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, _ *http.Request) {
	scim.Write(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []map[string]any{
			{"id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User", "description": "User Account"},
			{"id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group", "description": "Group"},
		},
	})
}

func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, _ *http.Request) {
	scim.Write(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []map[string]any{
			{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":          "User",
				"name":        "User",
				"endpoint":    "/Users",
				"schema":      "urn:ietf:params:scim:schemas:core:2.0:User",
			},
			{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":          "Group",
				"name":        "Group",
				"endpoint":    "/Groups",
				"schema":      "urn:ietf:params:scim:schemas:core:2.0:Group",
			},
		},
	})
}

func scimPage(r *http.Request) (filter string, start, count int) {
	q := r.URL.Query()
	start, _ = strconv.Atoi(q.Get("startIndex"))
	count, _ = strconv.Atoi(q.Get("count"))
	return q.Get("filter"), start, count
}

func decodeSCIM(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if err == io.EOF {
			scim.WriteErr(w, &scim.Error{Status: http.StatusBadRequest, Type: "invalidValue", Detail: "empty body"})
			return false
		}
		scim.WriteErr(w, &scim.Error{Status: http.StatusBadRequest, Type: "invalidSyntax", Detail: "invalid json"})
		return false
	}
	return true
}

func scimID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		scim.WriteErr(w, &scim.Error{Status: http.StatusNotFound, Type: "invalidValue", Detail: "not found"})
		return uuid.Nil, false
	}
	return id, true
}

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	filter, start, count := scimPage(r)
	out, err := s.scim.ListUsers(r.Context(), filter, start, count)
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	var in scim.UserResource
	if !decodeSCIM(w, r, &in) {
		return
	}
	out, err := s.scim.CreateUser(r.Context(), in, scimDefaultRole(r), s.clientIP(r))
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	if loc := out.Meta.Location; loc != "" {
		w.Header().Set("Location", loc)
	}
	scim.Write(w, http.StatusCreated, out)
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	out, err := s.scim.GetUser(r.Context(), id)
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMPutUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var in scim.UserResource
	if !decodeSCIM(w, r, &in) {
		return
	}
	out, err := s.scim.PutUser(r.Context(), id, in, s.clientIP(r))
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var in scim.PatchOp
	if !decodeSCIM(w, r, &in) {
		return
	}
	out, err := s.scim.PatchUser(r.Context(), id, in.Ops(), s.clientIP(r))
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	if err := s.scim.DeleteUser(r.Context(), id, s.clientIP(r)); err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusNoContent, nil)
}

func (s *Server) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	filter, start, count := scimPage(r)
	out, err := s.scim.ListGroups(r.Context(), filter, start, count)
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	var in scim.GroupResource
	if !decodeSCIM(w, r, &in) {
		return
	}
	out, err := s.scim.CreateGroup(r.Context(), in, s.clientIP(r))
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	if loc := out.Meta.Location; loc != "" {
		w.Header().Set("Location", loc)
	}
	scim.Write(w, http.StatusCreated, out)
}

func (s *Server) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	out, err := s.scim.GetGroup(r.Context(), id)
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMPutGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var in scim.GroupResource
	if !decodeSCIM(w, r, &in) {
		return
	}
	out, err := s.scim.PutGroup(r.Context(), id, in, s.clientIP(r))
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var in scim.PatchOp
	if !decodeSCIM(w, r, &in) {
		return
	}
	out, err := s.scim.PatchGroup(r.Context(), id, in.Ops(), s.clientIP(r))
	if err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusOK, out)
}

func (s *Server) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	if err := s.scim.DeleteGroup(r.Context(), id, s.clientIP(r)); err != nil {
		scim.WriteErr(w, err)
		return
	}
	scim.Write(w, http.StatusNoContent, nil)
}
