package filexfer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/keeppam/auth/internal/policy"
)

const (
	RDPProtocolDrive     = "rdp-drive"
	RDPProtocolClipboard = "rdp-clipboard"
)

// IngestRDPSession indexes files from guacd drive/clipboard staging after RDP session ends.
func (s *Service) IngestRDPSession(ctx context.Context, sessionID uuid.UUID, recordingsRoot string, snap *policy.Snapshot) error {
	if s == nil || recordingsRoot == "" {
		return nil
	}
	mode := policy.FileTransferDeny
	var clip, drive bool
	if snap != nil {
		mode = snap.EffectiveFileTransfer()
		rdp := snap.RDP()
		clip, drive = rdp.Clipboard, rdp.Drive
	}
	if policy.FileTransferDenied(mode) {
		return nil
	}
	capture := policy.FileTransferStoresBytes(mode)
	root := strings.TrimSpace(recordingsRoot)
	var firstErr error
	if drive {
		dir := filepath.Join(root, "rdp-drive", sessionID.String())
		if err := s.ingestRDPDir(ctx, sessionID, dir, RDPProtocolDrive, capture); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if clip {
		dir := filepath.Join(root, "rdp-clipboard", sessionID.String())
		if err := s.ingestRDPDir(ctx, sessionID, dir, RDPProtocolClipboard, capture); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) ingestRDPDir(ctx context.Context, sessionID uuid.UUID, root, protocol string, capture bool) error {
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = name
		}
		rel = filepath.ToSlash(rel)
		exists, err := s.rdpFileExists(ctx, sessionID, protocol, rel)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Size() > maxFileBytes {
			return fmt.Errorf("rdp file too large: %s", rel)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = s.SaveReader(ctx, SaveMeta{
			SessionID:  sessionID,
			Filename:   name,
			RemotePath: rel,
			Protocol:   protocol,
			Direction:  rdpDirection(rel),
			Capture:    capture,
		}, f, fi.Size())
		_ = f.Close()
		return err
	})
}

func rdpDirection(rel string) string {
	p := strings.ToLower(filepath.ToSlash(rel))
	if strings.Contains(p, "/upload/") || strings.HasPrefix(p, "upload/") {
		return "upload"
	}
	return "download"
}

func (s *Service) rdpFileExists(ctx context.Context, sessionID uuid.UUID, protocol, remotePath string) (bool, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM session_files
		WHERE session_id=$1 AND protocol=$2 AND remote_path=$3`,
		sessionID, protocol, remotePath).Scan(&n)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return n > 0, nil
}
