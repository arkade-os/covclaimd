package preimage_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkade-os/covclaimd/pkg/preimage"
)

func TestBuildPacket_RoundTrip(t *testing.T) {
	covclaimd, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	preimg := make([]byte, 32)
	for i := range preimg {
		preimg[i] = byte(i)
	}
	receiver := freshP2TR(t)

	pkt, err := preimage.BuildPacket(preimg, covclaimd.PubKey(), receiver)
	require.NoError(t, err)
	require.Equal(t, preimage.PacketType, pkt.Type())

	body, err := pkt.Serialize()
	require.NoError(t, err)

	decoded, err := preimage.DeserializeClaim(body)
	require.NoError(t, err)

	plaintext, err := preimage.Decrypt(covclaimd, decoded.Ciphertext)
	require.NoError(t, err)
	assert.Equal(t, preimg, plaintext)

	expectedScript, err := preimage.EnforcePayTo(receiver)
	require.NoError(t, err)
	assert.Equal(t, expectedScript, decoded.ArkadeScript)

	// The committed key must be the one the ciphertext was actually sealed to,
	// not merely well-formed: the packet is otherwise addressed to a covclaimd
	// that cannot open it, and no claim is ever made.
	assert.Equal(t, covclaimd.PubKey().SerializeCompressed(), decoded.CovclaimdPubKey)
	assert.True(t, decoded.AddressedTo(covclaimd.PubKey().SerializeCompressed()))

	// The ciphertext stays a pure ECIES blob — ephPub(33) || nonce(12) ||
	// ct+tag(48). Carrying the recipient in its own TLV is what keeps this
	// number 93 and Decrypt unaware that any of this happened.
	assert.Len(t, decoded.Ciphertext, 93)

	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	assert.False(t, decoded.AddressedTo(other.PubKey().SerializeCompressed()))
}

func TestBuildPacket_ValidatesInputs(t *testing.T) {
	covclaimd, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	receiver := freshP2TR(t)

	t.Run("preimage wrong length", func(t *testing.T) {
		_, err := preimage.BuildPacket(make([]byte, 31), covclaimd.PubKey(), receiver)
		assert.Error(t, err)
	})
	t.Run("covclaimd pubkey nil", func(t *testing.T) {
		_, err := preimage.BuildPacket(make([]byte, 32), nil, receiver)
		assert.Error(t, err)
	})
	t.Run("receiver wrong length", func(t *testing.T) {
		_, err := preimage.BuildPacket(make([]byte, 32), covclaimd.PubKey(), []byte{0x01})
		assert.Error(t, err)
	})
}

func freshP2TR(t *testing.T) []byte {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	out, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(priv.PubKey().SerializeCompressed()[1:]).
		Script()
	require.NoError(t, err)
	require.Len(t, out, 34)
	return out
}
