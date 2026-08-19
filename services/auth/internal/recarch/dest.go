package recarch

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Dest is NFS directory or SMB share.
type Dest interface {
	Kind() string
	Put(ctx context.Context, rel string, r io.Reader) error
	Get(ctx context.Context, rel string, w io.Writer) error
	Exists(ctx context.Context, rel string) bool
}

type nfsDest struct {
	root string
}

func newNFSDest(root string) (*nfsDest, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("nfs_path required")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	return &nfsDest{root: root}, nil
}

func (d *nfsDest) Kind() string { return "nfs" }

func (d *nfsDest) abs(rel string) (string, error) {
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "/"))
	if rel == "" || strings.Contains(rel, "..") {
		return "", fmt.Errorf("bad archive path")
	}
	p := filepath.Join(d.root, filepath.FromSlash(rel))
	if !strings.HasPrefix(p, filepath.Clean(d.root)+string(os.PathSeparator)) && p != filepath.Clean(d.root) {
		return "", fmt.Errorf("path outside archive dir")
	}
	return p, nil
}

func (d *nfsDest) Put(ctx context.Context, rel string, r io.Reader) error {
	_ = ctx
	p, err := d.abs(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, p)
}

func (d *nfsDest) Get(ctx context.Context, rel string, w io.Writer) error {
	_ = ctx
	p, err := d.abs(rel)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func (d *nfsDest) Exists(ctx context.Context, rel string) bool {
	_ = ctx
	p, err := d.abs(rel)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}
