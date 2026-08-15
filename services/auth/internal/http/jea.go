package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/policy"
	"github.com/keeppam/auth/internal/sshproxy"
)

func (s *Server) handleListCommandPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListCommandPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleGetCommandPack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.policy.GetCommandPack(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.CommandPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.CreateCommandPack(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdateCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.CommandPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.UpdateCommandPack(r.Context(), sess.UserID, id, in, clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteCommandPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.policy.DeleteCommandPack(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListSQLPacks(w http.ResponseWriter, r *http.Request) {
	list, err := s.policy.ListSQLPacks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"packs": list})
}

func (s *Server) handleGetSQLPack(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.policy.GetSQLPack(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreateSQLPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	var in policy.SQLPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.CreateSQLPack(r.Context(), sess.UserID, in, clientIP(r), r.UserAgent())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleUpdateSQLPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in policy.SQLPackInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	p, err := s.policy.UpdateSQLPack(r.Context(), sess.UserID, id, in, clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteSQLPack(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.policy.DeleteSQLPack(r.Context(), sess.UserID, id, clientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) resolveSQLPack(ctx context.Context, userID, assetID uuid.UUID, roles []string, bypass bool, ticketID string) (policy.SQLPack, bool) {
	ev, err := s.policy.Evaluate(ctx, policy.AccessCheck{
		UserID: userID, AssetID: assetID, RoleNames: roles, Bypass: bypass, TicketID: ticketID, SkipRisk: true,
	})
	if err != nil || !ev.OK || ev.SQLPolicyPackID == nil {
		return policy.SQLPack{}, false
	}
	pack, err := s.policy.GetSQLPack(ctx, *ev.SQLPolicyPackID)
	if err != nil {
		return policy.SQLPack{}, false
	}
	return pack, true
}

func (s *Server) buildSSHSessionOpts(ctx context.Context, userID, assetID, sessionID uuid.UUID, roles []string, bypass bool, ticketID string, inject func([]byte)) sshproxy.SessionOpts {
	opts := sshproxy.SessionOpts{LocalInject: inject}
	var pack policy.CommandPack
	hasPack := false
	ev, err := s.policy.Evaluate(ctx, policy.AccessCheck{
		UserID: userID, AssetID: assetID, RoleNames: roles, Bypass: bypass, TicketID: ticketID, SkipRisk: true,
	})
	if err == nil && ev.OK && ev.CommandPolicyPackID != nil {
		if p, err := s.policy.GetCommandPack(ctx, *ev.CommandPolicyPackID); err == nil {
			pack, hasPack = p, true
		}
	}
	if !hasPack {
		return opts
	}
	opts.QuietEcho = true
	opts.Guard = sshproxy.NewCommandGuard(func(line string) bool {
		if !policy.AllowSSHLine(pack, true, line) {
			return false
		}
		op := policy.SSHOperation(line)
		if op == "" {
			return true
		}
		ev, err := s.policy.CheckOpRisk(ctx, policy.AccessCheck{
			UserID: userID, AssetID: assetID, RoleNames: roles, Bypass: bypass,
			TicketID: ticketID, Operation: op,
		})
		return err != nil || ev.OK
	})
	opts.OnDenied = func(line string) {
		bg := context.Background()
		if kind, ok := policy.FileTransferCommand(line); ok {
			_ = s.audit.Record(bg, &userID, "session.dlp.denied", "session", sessionID.String(), "", "ssh", map[string]any{
				"command": line, "kind": kind, "reason": "ssh file transfer denied by DLP",
			})
			_ = s.sessionsvc.AddEvent(bg, sessionID, "dlp", map[string]any{
				"command": line, "kind": kind, "reason": "ssh file transfer denied by DLP",
			})
			return
		}
		if policy.AllowSSHLine(pack, true, line) {
			_ = s.audit.Record(bg, &userID, "session.risk.denied", "session", sessionID.String(), "", "ssh", map[string]any{
				"command": line, "operation": policy.SSHOperation(line),
			})
			_ = s.sessionsvc.AddEvent(bg, sessionID, "risk", map[string]any{
				"command": line, "operation": policy.SSHOperation(line),
			})
			return
		}
		_ = s.audit.Record(bg, &userID, "session.command.denied", "session", sessionID.String(), "", "jea", map[string]any{
			"command": line, "pack": pack.Name, "mode": pack.Mode,
		})
		_ = s.sessionsvc.AddEvent(bg, sessionID, "command_denied", map[string]any{
			"command": line, "pack": pack.Name,
		})
	}
	return opts
}
