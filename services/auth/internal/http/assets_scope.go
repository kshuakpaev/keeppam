package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/assets"
	"github.com/keeppam/auth/internal/rbac"
	"github.com/keeppam/auth/internal/session"
)

func (s *Server) entitledSet(r *http.Request, sess session.Session) (map[uuid.UUID]struct{}, error) {
	ids, err := s.policy.EntitledAssetIDs(r.Context(), sess.UserID, sess.Roles, time.Now())
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out, nil
}

func applyAssetEntitlement(list []assets.Asset, full bool, set map[uuid.UUID]struct{}) {
	for i := range list {
		list[i].Entitled = full
		if !full {
			_, list[i].Entitled = set[list[i].ID]
		}
		if !list[i].Entitled {
			list[i].Accounts = nil
		}
	}
}

// assetListScope: all (inventory/admin), entitled (ACL/owner only), catalog (browse to request).
func (s *Server) assetListScope(r *http.Request, sess session.Session) string {
	full := rbac.SeesFullAssetCatalog(sess.Permissions)
	raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	switch raw {
	case "catalog":
		if full || rbac.HasPermission(sess.Permissions, "access.request") {
			return "catalog"
		}
		return "entitled"
	case "all":
		if full {
			return "all"
		}
		return "entitled"
	case "entitled":
		return "entitled"
	default:
		if full {
			return "all"
		}
		return "entitled"
	}
}
