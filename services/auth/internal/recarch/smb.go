package recarch

import (
	"context"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

type smbDest struct {
	host, share, user, domain, password string
}

func newSMBDest(host, share, user, domain, password string) (*smbDest, error) {
	host = strings.TrimSpace(host)
	share = strings.TrimSpace(strings.ReplaceAll(share, "\\", "/"))
	share = strings.Trim(share, "/")
	if host == "" || share == "" || user == "" || password == "" {
		return nil, fmt.Errorf("smb host, share, user and password required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "445")
	}
	return &smbDest{host: host, share: share, user: user, domain: domain, password: password}, nil
}

func (d *smbDest) Kind() string { return "smb" }

func (d *smbDest) withFS(ctx context.Context, fn func(*smb2.Share) error) error {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", d.host)
	if err != nil {
		return fmt.Errorf("smb dial: %w", err)
	}
	defer conn.Close()
	s, err := (&smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     d.user,
			Password: d.password,
			Domain:   d.domain,
		},
	}).Dial(conn)
	if err != nil {
		return fmt.Errorf("smb session: %w", err)
	}
	defer s.Logoff()
	fs, err := s.Mount(d.share)
	if err != nil {
		return fmt.Errorf("smb mount: %w", err)
	}
	defer fs.Umount()
	return fn(fs)
}

func smbRel(rel string) (string, error) {
	rel = path.Clean("/" + strings.ReplaceAll(rel, "\\", "/"))
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" || strings.Contains(rel, "..") {
		return "", fmt.Errorf("bad archive path")
	}
	return rel, nil
}

func (d *smbDest) Put(ctx context.Context, rel string, r io.Reader) error {
	rel, err := smbRel(rel)
	if err != nil {
		return err
	}
	return d.withFS(ctx, func(fs *smb2.Share) error {
		dir := path.Dir(rel)
		if dir != "." {
			_ = fs.MkdirAll(dir, 0o755)
		}
		f, err := fs.Create(rel)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, r)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func (d *smbDest) Get(ctx context.Context, rel string, w io.Writer) error {
	rel, err := smbRel(rel)
	if err != nil {
		return err
	}
	return d.withFS(ctx, func(fs *smb2.Share) error {
		f, err := fs.Open(rel)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
}

func (d *smbDest) Exists(ctx context.Context, rel string) bool {
	rel, err := smbRel(rel)
	if err != nil {
		return false
	}
	ok := false
	_ = d.withFS(ctx, func(fs *smb2.Share) error {
		_, err := fs.Stat(rel)
		ok = err == nil
		return nil
	})
	return ok
}
