package httpapi

import (
	"net/http"
	"strconv"

	"github.com/keeppam/auth/internal/analytics"
)

func (s *Server) handleAnalyticsOverview(w http.ResponseWriter, r *http.Request) {
	f := analytics.OverviewFilter{WindowHours: 24}
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.WindowHours = n
		}
	}
	f.Severity = r.URL.Query().Get("severity")
	f.Code = r.URL.Query().Get("code")
	out, err := s.analytics.OverviewFiltered(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
