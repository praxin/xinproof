package engine

import (
	"context"
	"fmt"

	"github.com/praxin/xinproof/internal/discover"
)

// Multi dispatches each backup to the first engine that supports its format.
type Multi []Engine

func (m Multi) pick(d discover.Detection) Engine {
	for _, e := range m {
		if e.Supports(d) {
			return e
		}
	}
	return nil
}

func (m Multi) Supports(d discover.Detection) bool { return m.pick(d) != nil }

func (m Multi) Analyzer(d discover.Detection) Analyzer {
	if e := m.pick(d); e != nil {
		return e.Analyzer(d)
	}
	return nil
}

func (m Multi) Start(ctx context.Context, d discover.Detection) (Session, error) {
	if e := m.pick(d); e != nil {
		return e.Start(ctx, d)
	}
	return nil, fmt.Errorf("no engine for format %s", d.Format)
}
