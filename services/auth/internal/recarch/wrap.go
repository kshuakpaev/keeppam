package recarch

import (
	"context"

	"github.com/keeppam/auth/internal/recstore"
)

type wrap struct {
	recstore.Store
	a *Service
}

func Wrap(inner recstore.Store, a *Service) recstore.Store {
	if inner == nil || a == nil {
		return inner
	}
	return &wrap{Store: inner, a: a}
}

func (w *wrap) EnsureLocal(ctx context.Context, absPath string) error {
	if err := w.Store.EnsureLocal(ctx, absPath); err == nil {
		return nil
	} else if w.a.Restore(ctx, absPath) == nil {
		return nil
	} else {
		return err
	}
}

func (w *wrap) Exists(ctx context.Context, absPath string) bool {
	if w.Store.Exists(ctx, absPath) {
		return true
	}
	return w.a.Has(ctx, absPath)
}
