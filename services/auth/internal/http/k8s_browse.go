package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/k8sproxy"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/session"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) k8sBrowseSession(w http.ResponseWriter, r *http.Request) (sessionsvc.Session, bool) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return sessionsvc.Session{}, false
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return sessionsvc.Session{}, false
	}
	if sess.UserID != row.UserID && !rbac.HasPermission(sess.Permissions, "users.write") {
		writeErr(w, http.StatusForbidden, "forbidden")
		return sessionsvc.Session{}, false
	}
	if row.Protocol != "kubectl" {
		writeErr(w, http.StatusBadRequest, "not a kubectl session")
		return sessionsvc.Session{}, false
	}
	if row.Status != "pending" && row.Status != "active" {
		writeErr(w, http.StatusGone, "session ended")
		return sessionsvc.Session{}, false
	}
	if s.k8s == nil {
		writeErr(w, http.StatusServiceUnavailable, "k8s gateway disabled")
		return sessionsvc.Session{}, false
	}
	return row, true
}

func (s *Server) handleK8sCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.k8sBrowseSession(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": k8sproxy.Catalog()})
}

func (s *Server) handleK8sNamespaces(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	allowed := k8sproxy.NormalizeNamespaces(row.K8sNamespaces)
	if len(allowed) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{"namespaces": allowed, "acl": true})
		return
	}
	code, body, err := s.k8s.Call(r.Context(), row, http.MethodGet, "/api/v1/namespaces")
	if s.writeK8sCallErr(w, r, row, code, body, err) {
		return
	}
	names := make([]string, 0)
	for _, it := range k8sproxy.SummarizeList(body) {
		if it.Name != "" {
			names = append(names, it.Name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"namespaces": names, "acl": false})
}

func (s *Server) handleK8sList(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	kind, err := k8sproxy.LookupKind(r.URL.Query().Get("resource"), r.URL.Query().Get("group"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	path, err := k8sproxy.APIPath(kind, r.URL.Query().Get("namespace"), "")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	code, body, err := s.k8s.Call(r.Context(), row, http.MethodGet, path)
	if s.writeK8sCallErr(w, r, row, code, body, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource": kind.Resource, "group": kind.Group, "items": k8sproxy.SummarizeList(body),
	})
}

func (s *Server) handleK8sGet(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	kind, err := k8sproxy.LookupKind(r.URL.Query().Get("resource"), r.URL.Query().Get("group"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	path, err := k8sproxy.APIPath(kind, r.URL.Query().Get("namespace"), name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	code, body, err := s.k8s.Call(r.Context(), row, http.MethodGet, path)
	if s.writeK8sCallErr(w, r, row, code, body, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource": kind.Resource, "group": kind.Group, "object": json.RawMessage(body),
	})
}

func (s *Server) handleK8sApply(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		Manifest  string `json:"manifest"`
		Namespace string `json:"namespace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	results, err := s.k8s.ApplyManifests(r.Context(), row, []byte(body.Manifest), body.Namespace)
	if err != nil {
		s.writeK8sOpErr(w, r, row, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleK8sReplace(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		Object map[string]any `json:"object"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Object) == 0 {
		writeErr(w, http.StatusBadRequest, "object required")
		return
	}
	code, raw, err := s.k8s.ReplaceObject(r.Context(), row, body.Object)
	if s.writeK8sCallErr(w, r, row, code, raw, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": json.RawMessage(raw), "status": code})
}

func (s *Server) handleK8sDelete(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Resource  string `json:"resource"`
		Group     string `json:"group"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	code, raw, err := s.k8s.DeleteObject(r.Context(), row, body.Resource, body.Group, body.Namespace, body.Name)
	if s.writeK8sCallErr(w, r, row, code, raw, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": code, "object": json.RawMessage(raw)})
}

func (s *Server) handleK8sExecOnce(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		Container string `json:"container"`
		Command   any    `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cmd := commandFromJSON(body.Command)
	if len(cmd) == 0 {
		writeErr(w, http.StatusBadRequest, "command required")
		return
	}
	res, err := s.k8s.ExecOnce(r.Context(), row, body.Namespace, body.Pod, body.Container, cmd)
	if err != nil {
		s.writeK8sOpErr(w, r, row, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleK8sPortForwardHTTP(w http.ResponseWriter, r *http.Request) {
	row, ok := s.k8sBrowseSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		Port      int    `json:"port"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Body      string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := s.k8s.PortForwardHTTP(r.Context(), row, body.Namespace, body.Pod, body.Port, body.Method, body.Path, []byte(body.Body))
	if err != nil {
		s.writeK8sOpErr(w, r, row, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func commandFromJSON(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			s, _ := it.(string)
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		if strings.ContainsAny(s, " \t") {
			return []string{"/bin/sh", "-c", s}
		}
		return []string{s}
	default:
		return nil
	}
}

func (s *Server) writeK8sCallErr(w http.ResponseWriter, r *http.Request, row sessionsvc.Session, code int, body []byte, err error) bool {
	if se, ok := isStepUpErr(err); ok {
		s.writeStepUpChallenge(w, r, session.Session{UserID: row.UserID, Username: row.Username}, se.Result, row.AssetID, row.ID)
		return true
	}
	if err != nil && len(body) == 0 {
		if code < 400 {
			code = http.StatusBadGateway
		}
		writeErr(w, code, err.Error())
		return true
	}
	if code >= 300 {
		writeK8sProxyErr(w, code, body)
		return true
	}
	return false
}

func (s *Server) writeK8sOpErr(w http.ResponseWriter, r *http.Request, row sessionsvc.Session, err error) {
	if se, ok := isStepUpErr(err); ok {
		s.writeStepUpChallenge(w, r, session.Session{UserID: row.UserID, Username: row.Username}, se.Result, row.AssetID, row.ID)
		return
	}
	code := k8sproxy.HTTPStatus(err)
	if code < 400 {
		code = http.StatusBadGateway
	}
	writeErr(w, code, err.Error())
}

func writeK8sProxyErr(w http.ResponseWriter, code int, body []byte) {
	msg := strings.TrimSpace(string(body))
	var st struct {
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if json.Unmarshal(body, &st) == nil {
		if st.Message != "" {
			msg = st.Message
		} else if st.Reason != "" {
			msg = st.Reason
		}
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if msg == "" {
		msg = "upstream error"
	}
	if code < 400 {
		code = http.StatusBadGateway
	}
	writeErr(w, code, msg)
}
