package preimage

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revealFixture builds a valid {address, ciphertext, arkadeScript} triple
// addressed to secret's pubkey.
type revealFixture struct {
	secret       *btcec.PrivateKey
	swapAddress  string
	ciphertext   []byte
	arkadeScript []byte
	pkScript     []byte
}

func newRevealFixture(t *testing.T) revealFixture {
	t.Helper()
	secret, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	receiverPk := freshTaprootScript(t) // defined in plugin_internal_test.go
	arkadeScript, err := EnforcePayTo(receiverPk)
	require.NoError(t, err)

	preimg := make([]byte, 32)
	ct, err := Encrypt(secret.PubKey(), preimg)
	require.NoError(t, err)

	// Any P2TR key works as the swap output key for address-decode purposes.
	tapKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	addr, err := (&arklib.Address{
		HRP:        "tark",
		Signer:     secret.PubKey(),
		VtxoTapKey: tapKey.PubKey(),
	}).EncodeV0()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey.PubKey())
	require.NoError(t, err)

	return revealFixture{
		secret:       secret,
		swapAddress:  addr,
		ciphertext:   ct,
		arkadeScript: arkadeScript,
		pkScript:     pkScript,
	}
}

func TestRecorder_Submit_Valid(t *testing.T) {
	f := newRevealFixture(t)
	reg := NewInMemoryRegistry()
	r, err := NewRecorder(reg, f.secret)
	require.NoError(t, err)

	require.NoError(t, r.Submit(context.Background(), f.swapAddress, f.ciphertext, f.arkadeScript))

	got, ok := reg.Lookup(context.Background(), hex.EncodeToString(f.pkScript))
	require.True(t, ok, "valid submission must be stored under the derived pkScript")
	assert.Equal(t, f.arkadeScript, got.Packet.ArkadeScript)
}

func TestRecorder_Submit_BadAddress(t *testing.T) {
	f := newRevealFixture(t)
	r, err := NewRecorder(NewInMemoryRegistry(), f.secret)
	require.NoError(t, err)
	err = r.Submit(context.Background(), "not-an-address", f.ciphertext, f.arkadeScript)
	require.Error(t, err)
}

func TestRecorder_Submit_UndecryptableCiphertext(t *testing.T) {
	f := newRevealFixture(t)
	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	r, err := NewRecorder(NewInMemoryRegistry(), other) // wrong key
	require.NoError(t, err)
	err = r.Submit(context.Background(), f.swapAddress, f.ciphertext, f.arkadeScript)
	require.Error(t, err)
}

func TestRecorder_Submit_BadArkadeScript(t *testing.T) {
	f := newRevealFixture(t)
	r, err := NewRecorder(NewInMemoryRegistry(), f.secret)
	require.NoError(t, err)
	err = r.Submit(context.Background(), f.swapAddress, f.ciphertext, []byte{0xde, 0xad, 0xbe, 0xef})
	require.Error(t, err)
}

func TestRecorder_Submit_WrongPreimageLength(t *testing.T) {
	f := newRevealFixture(t)
	// A ciphertext that decrypts cleanly but to a non-32-byte plaintext.
	ct, err := Encrypt(f.secret.PubKey(), make([]byte, 16))
	require.NoError(t, err)
	r, err := NewRecorder(NewInMemoryRegistry(), f.secret)
	require.NoError(t, err)
	err = r.Submit(context.Background(), f.swapAddress, ct, f.arkadeScript)
	require.Error(t, err)
}
