package keygen

import (
	"context"

	"github.com/Mattias-/vanity-ssh-keygen/pkg/keygen/ed25519"
)

type Worker struct {
	results chan SSHKey
	count   int64

	Matchfunc func(SSHKey) bool
	Keyfunc   func() SSHKey
}

func (w *Worker) Run(ctx context.Context) {
	k := w.Keyfunc()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		w.count += 1
		k.Generate()
		if w.Matchfunc(k) {
			// A result was found!
			break
		}
		if ed, ok := k.(*ed25519.Ed); ok {
			ed.ReleaseBuf()
		}
	}
	select {
	case w.results <- k:
	case <-ctx.Done():
	}
}

func (w *Worker) Count() int64 {
	return w.count
}

func (w *Worker) SetResultChan(results chan SSHKey) {
	w.results = results
}
