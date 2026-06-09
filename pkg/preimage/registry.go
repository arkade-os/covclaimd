package preimage

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
)

// Registration is a maker's standing request for covclaimd to claim a
// preimage-gated VTXO funded at PkScript, using the (ECIES) Packet revealed
// out-of-band via RevealService instead of through the Arkade extension.
type Registration struct {
	PkScript []byte      // 34-byte P2TR script of the swap (funding) output
	Packet   ClaimPacket // ECIES ciphertext + plaintext arkade script
}

// Registry stores reveal Registrations keyed by the hex-encoded funding
// pkScript. It is a port: the in-memory implementation below is the v1 default;
// a durable implementation can satisfy the same interface later with no caller
// changes.
type Registry interface {
	Add(ctx context.Context, r Registration) error
	Lookup(ctx context.Context, pkScriptHex string) (*Registration, bool)
	Remove(ctx context.Context, pkScriptHex string) error
}

// InMemoryRegistry is a process-local Registry. Registrations are lost on
// restart (makers re-submit); that is acceptable for v1.
type InMemoryRegistry struct {
	mu sync.RWMutex
	m  map[string]Registration
}

func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{m: make(map[string]Registration)}
}

// Add stores r keyed by hex(r.PkScript). Last write wins for a given key.
func (r *InMemoryRegistry) Add(_ context.Context, reg Registration) error {
	if len(reg.PkScript) == 0 {
		return errors.New("registration pkScript must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[hex.EncodeToString(reg.PkScript)] = reg.clone()
	return nil
}

// Lookup returns a copy of the registration for pkScriptHex, if present.
func (r *InMemoryRegistry) Lookup(_ context.Context, pkScriptHex string) (*Registration, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.m[pkScriptHex]
	if !ok {
		return nil, false
	}
	cp := reg.clone()
	return &cp, true
}

// Remove deletes the registration for pkScriptHex (no-op if absent).
func (r *InMemoryRegistry) Remove(_ context.Context, pkScriptHex string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, pkScriptHex)
	return nil
}

// clone deep-copies the byte slices so stored state can't be mutated through a
// returned pointer (or a caller-retained input slice).
func (r Registration) clone() Registration {
	return Registration{
		PkScript: slices.Clone(r.PkScript),
		Packet: ClaimPacket{
			Ciphertext:   slices.Clone(r.Packet.Ciphertext),
			ArkadeScript: slices.Clone(r.Packet.ArkadeScript),
		},
	}
}
