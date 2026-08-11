package preimage

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The filter is the only place covclaimd hands a string to another process and
// gets no feedback when it is wrong: an expression that compiles but matches
// nothing is indistinguishable from a quiet stream. So pin its shape, and pin
// that the needle it carries is the packet's own bytes rather than a second
// spelling of them.
func TestPluginFilter_SelectsOurOwnPackets(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := priv.PubKey().SerializeCompressed()

	p := &plugin{pubKey: pubKey}
	filter := p.Filter()

	// arkd's env: has() is the presence guard, hasPacket() the type test, and
	// tx.extension[t] the hex of that packet's body.
	assert.Equal(t,
		"has(tx.extension) && hasPacket(tx.extension, 4) && tx.extension[4].contains("+
			"'030021"+hex.EncodeToString(pubKey)+"')",
		filter,
	)

	// The needle has to be a substring of a real serialized packet, or the
	// subscription silently returns nothing. Check against one, not by
	// re-deriving the bytes the same way Filter did.
	body, err := (&ClaimPacket{
		Ciphertext:      []byte{0xde, 0xad, 0xbe, 0xef},
		ArkadeScript:    []byte{0x51},
		CovclaimdPubKey: pubKey,
	}).Serialize()
	require.NoError(t, err)
	assert.Contains(t, hex.EncodeToString(body), needleOf(t, filter))
}

// A packet sealed to a different covclaimd must not satisfy our filter — that
// is the whole point of committing the key, and it is what lets two
// deployments share one stream.
func TestPluginFilter_DoesNotSelectAnotherCovclaimdsPackets(t *testing.T) {
	ours, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	theirs, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	p := &plugin{pubKey: ours.PubKey().SerializeCompressed()}

	body, err := (&ClaimPacket{
		Ciphertext:      []byte{0xde, 0xad, 0xbe, 0xef},
		ArkadeScript:    []byte{0x51},
		CovclaimdPubKey: theirs.PubKey().SerializeCompressed(),
	}).Serialize()
	require.NoError(t, err)
	assert.NotContains(t, hex.EncodeToString(body), needleOf(t, p.Filter()))
}

// Both sides of the wire hex-encode with encoding/hex. arkd builds the haystack
// with it in txfilter.NewTx; if Filter ever emitted uppercase, contains() would
// match nothing and no claim would ever fire.
func TestPluginFilter_NeedleIsLowercase(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	p := &plugin{pubKey: priv.PubKey().SerializeCompressed()}

	needle := needleOf(t, p.Filter())
	assert.NotEmpty(t, needle)
	for _, r := range needle {
		assert.NotContains(t, "ABCDEF", string(r), "needle must be lowercase hex")
	}
}

// needleOf pulls the quoted contains() argument back out of the expression.
func needleOf(t *testing.T, filter string) string {
	t.Helper()
	const open = ".contains('"
	i := len(filter)
	for j := 0; j+len(open) <= len(filter); j++ {
		if filter[j:j+len(open)] == open {
			i = j + len(open)
			break
		}
	}
	require.Less(t, i, len(filter), "filter has no contains() argument: %s", filter)
	for k := i; k < len(filter); k++ {
		if filter[k] == '\'' {
			return filter[i:k]
		}
	}
	t.Fatalf("unterminated contains() argument: %s", filter)
	return ""
}
