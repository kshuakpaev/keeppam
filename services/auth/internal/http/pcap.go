package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/keeppam/auth/internal/pcapx"
	"github.com/keeppam/auth/internal/sessionsvc"
)

func (s *Server) handleExportPCAP(w http.ResponseWriter, r *http.Request) {
	sess := mustSess(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := s.sessionsvc.Get(r.Context(), id)
	if err != nil {
		if sessionsvc.IsNotFound(err) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.sessionVisible(r.Context(), sess, row) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.canViewSessionIO(sess, row) {
		writeErr(w, http.StatusForbidden, "session I/O hidden")
		return
	}
	path, err := s.sessionsvc.RecordingFile(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if side := pcapSibling(path); side != path {
		if st, err := os.Stat(side); err == nil && st.Size() > 24 {
			path = side
		}
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "recording not found")
		return
	}
	defer f.Close()
	hdr := make([]byte, 4)
	n, _ := io.ReadFull(f, hdr)
	name := id.String() + ".pcap"
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	if n == 4 && isPCAP(hdr) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.audit.Record(r.Context(), &sess.UserID, "session.export_pcap", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"native": true})
		_, _ = io.Copy(w, f)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit.Record(r.Context(), &sess.UserID, "session.export_pcap", "session", id.String(), s.clientIP(r), r.UserAgent(), map[string]any{"native": false})
	if err := pcapx.WriteStreamFrom(w, f); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func pcapSibling(path string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + ".pcap"
	}
	return strings.TrimSuffix(path, ext) + ".pcap"
}

func isPCAP(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return bytes.Equal(b[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) ||
		bytes.Equal(b[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}) ||
		bytes.Equal(b[:4], []byte{0x4d, 0x3c, 0xb2, 0xa1}) ||
		bytes.Equal(b[:4], []byte{0xa1, 0xb2, 0x3c, 0x4d})
}
