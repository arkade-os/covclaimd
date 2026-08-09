package preimage

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findClaimClosure's failure is the only account anyone gets of why a revealed
// preimage did not turn into a claim. It used to be one sentence covering four
// unrelated causes — wrong contract shape, wrong preimage, wrong signer key —
// so these pin that each names itself. The messages are load-bearing: they are
// read by an operator with a stuck swap and no other instrument.
func TestFindClaimClosure_NamesTheCause(t *testing.T) {
	preimage := bytes.Repeat([]byte{0x42}, 32)
	receiver := fixedReceiver(t)
	server := fixedPub(t, strings.Repeat("02", 32))
	emulator := fixedPub(t, strings.Repeat("03", 32))

	enforcement, err := EnforcePayTo(receiver)
	require.NoError(t, err)
	tweaked := arkade.ComputeArkadeScriptPublicKey(emulator, arkade.ArkadeScriptHash(enforcement))

	claimable, err := CovenantClaimClosure(btcutil.Hash160(preimage), receiver, server, emulator)
	require.NoError(t, err)

	t.Run("no condition closure at all", func(t *testing.T) {
		vs := &script.TapscriptsVtxoScript{}
		_, err := findClaimClosure(vs, server, tweaked, preimage)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no ConditionMultisigClosure")
	})

	// The realistic wrong-contract-shape case: a taptree that is perfectly
	// well-formed and simply is not a claimable contract. The empty-taptree
	// case above cannot distinguish "no leaves" from "no leaves of this kind",
	// and it is the second that an operator actually meets.
	t.Run("leaves exist but none is a condition closure", func(t *testing.T) {
		vs := &script.TapscriptsVtxoScript{Closures: []script.Closure{
			&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, tweaked}},
		}}
		_, err := findClaimClosure(vs, server, tweaked, preimage)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no ConditionMultisigClosure")
		// Counts what it did find, so "wrong shape" is separable from "empty".
		assert.Contains(t, err.Error(), "1 closure(s)")
	})

	t.Run("condition closures exist but none commits to this preimage", func(t *testing.T) {
		other, err := CovenantClaimClosure(
			btcutil.Hash160(bytes.Repeat([]byte{0x99}, 32)), receiver, server, emulator,
		)
		require.NoError(t, err)
		vs := &script.TapscriptsVtxoScript{Closures: []script.Closure{other}}

		_, err = findClaimClosure(vs, server, tweaked, preimage)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "commit to HASH160 of this preimage")
		// Names the count it searched, so "none matched" is separable from
		// "there were none to match".
		assert.Contains(t, err.Error(), "none of 1")
	})

	t.Run("preimage matches but the keys do not", func(t *testing.T) {
		vs := &script.TapscriptsVtxoScript{Closures: []script.Closure{claimable}}
		stranger := fixedPub(t, strings.Repeat("04", 32))

		_, err := findClaimClosure(vs, stranger, tweaked, preimage)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "2-of-2")
		// The keys it wanted, so a misconfigured signer is visible as a diff
		// rather than inferred.
		assert.Contains(t, err.Error(), "check the configured signer key")
	})

	t.Run("the matching closure is still found", func(t *testing.T) {
		vs := &script.TapscriptsVtxoScript{Closures: []script.Closure{claimable}}
		found, err := findClaimClosure(vs, server, tweaked, preimage)
		require.NoError(t, err)
		assert.NotNil(t, found)
	})
}
