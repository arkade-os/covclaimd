package preimage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryRegistry_AddLookupRemove(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()

	pkScript := []byte{0x51, 0x20}
	pkScript = append(pkScript, make([]byte, 32)...)
	key := "5120" + "0000000000000000000000000000000000000000000000000000000000000000"

	_, ok := r.Lookup(ctx, key)
	require.False(t, ok, "lookup on empty registry must miss")

	require.NoError(t, r.Add(ctx, Registration{
		PkScript: pkScript,
		Packet:   ClaimPacket{Ciphertext: []byte{0x01}, ArkadeScript: []byte{0x02}},
	}))

	got, ok := r.Lookup(ctx, key)
	require.True(t, ok)
	assert.Equal(t, pkScript, got.PkScript)
	assert.Equal(t, []byte{0x01}, got.Packet.Ciphertext)

	require.NoError(t, r.Remove(ctx, key))
	_, ok = r.Lookup(ctx, key)
	require.False(t, ok, "lookup after remove must miss")
}

func TestInMemoryRegistry_AddLastWriteWins(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	pkScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	key := "5120" + "0000000000000000000000000000000000000000000000000000000000000000"

	require.NoError(t, r.Add(ctx, Registration{PkScript: pkScript, Packet: ClaimPacket{Ciphertext: []byte{0xaa}}}))
	require.NoError(t, r.Add(ctx, Registration{PkScript: pkScript, Packet: ClaimPacket{Ciphertext: []byte{0xbb}}}))

	got, ok := r.Lookup(ctx, key)
	require.True(t, ok)
	assert.Equal(t, byte(0xbb), got.Packet.Ciphertext[0], "second Add must overwrite the first")
}

func TestInMemoryRegistry_AddRejectsEmptyPkScript(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Add(context.Background(), Registration{
		Packet: ClaimPacket{Ciphertext: []byte{0x01}, ArkadeScript: []byte{0x02}},
	})
	require.Error(t, err)
}

func TestInMemoryRegistry_LookupReturnsCopy(t *testing.T) {
	ctx := context.Background()
	r := NewInMemoryRegistry()
	pkScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	key := "5120" + "0000000000000000000000000000000000000000000000000000000000000000"
	require.NoError(t, r.Add(ctx, Registration{PkScript: pkScript, Packet: ClaimPacket{Ciphertext: []byte{0x01}, ArkadeScript: []byte{0x02}}}))

	got, ok := r.Lookup(ctx, key)
	require.True(t, ok)
	got.Packet.Ciphertext[0] = 0xff // mutate the returned copy

	again, ok := r.Lookup(ctx, key)
	require.True(t, ok)
	assert.Equal(t, byte(0x01), again.Packet.Ciphertext[0], "stored registration must be unaffected by caller mutation")
}
