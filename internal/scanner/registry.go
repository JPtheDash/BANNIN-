package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/jyotidash/bannin/pkg/plugin"
)

// Registry holds the set of Scanner plugins BANNIN knows about, keyed by
// plugin.Scanner.Name(). Since plugins/* depend only on pkg/plugin (never
// on internal/), plugins can't register themselves the way database/sql
// drivers do; the composition root (cmd/bannin) imports each concrete
// plugin package and calls Register against DefaultRegistry instead.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]plugin.Scanner
}

// NewRegistry returns an empty Registry. Most callers want
// DefaultRegistry; NewRegistry exists mainly so tests can avoid mutating
// global state.
func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]plugin.Scanner)}
}

// DefaultRegistry is the process-wide registry concrete plugin packages
// register themselves against.
var DefaultRegistry = NewRegistry()

// Register adds s to the registry under s.Name(). It panics on a
// duplicate name — two plugins claiming the same identifier is a
// programming error, not a runtime condition callers should handle.
func (r *Registry) Register(s plugin.Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := s.Name()
	if _, exists := r.scanners[name]; exists {
		panic(fmt.Sprintf("scanner: Register called twice for plugin %q", name))
	}
	r.scanners[name] = s
}

// Lookup returns the registered Scanner for name, if any.
func (r *Registry) Lookup(name string) (plugin.Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scanners[name]
	return s, ok
}

// Names returns the registered plugin names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
