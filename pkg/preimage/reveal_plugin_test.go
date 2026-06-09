package preimage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRevealPlugin_Match_HitFromRegistry(t *testing.T) {
	f := newFixture(t) // from plugin_internal_test.go

	reg := NewInMemoryRegistry()
	ct, err := Encrypt(f.covclaimdPriv.PubKey(), f.preimg)
	require.NoError(t, err)
	require.NoError(t, reg.Add(context.Background(), Registration{
		PkScript: f.expectedPk,
		Packet:   ClaimPacket{Ciphertext: ct, ArkadeScript: f.arkadeScript},
	}))

	rp := &revealPlugin{claimer: f.plugin.claimer, reg: reg}

	tx, _ := f.makeClaimTx(nil) // fund tx with the VHTLC output, NO extension
	matched, ok := rp.matchFromRegistry(context.Background(), tx)
	require.True(t, ok)
	require.NotNil(t, matched)
	require.Equal(t, uint32(1), matched.Outpoint.Index)
	require.Equal(t, f.preimg, matched.Credentials.Preimage)
}

func TestRevealPlugin_Match_MissWhenNotRegistered(t *testing.T) {
	f := newFixture(t)
	reg := NewInMemoryRegistry() // empty
	rp := &revealPlugin{claimer: f.plugin.claimer, reg: reg}

	tx, _ := f.makeClaimTx(nil)
	_, ok := rp.matchFromRegistry(context.Background(), tx)
	require.False(t, ok, "unregistered funding output must be a miss")
}
