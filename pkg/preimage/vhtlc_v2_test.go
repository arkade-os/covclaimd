package preimage

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Vectors lifted from @arkade-os/sdk's VHTLC.ScriptV2 — the construction the
// makers this bot serves actually fund. Everything else in this package is
// tested against taptrees this repo builds itself, which cannot catch the one
// failure that matters: the SDK moving its leaf bytes out from under us. The
// preimage condition is the whole of the v1/v2 difference (v1 omits the
// SIZE 32 EQUALVERIFY prefix), so a covclaimd built for the wrong version
// parses the taptree fine and then silently matches nothing.
//
// Regenerate by constructing VHTLC.ScriptV2 with the keys below and printing
// pkScript, encode(), and nonInteractiveClaimScript.
const (
	// Full 8-leaf taptree, BIP-371 encoded: both optional non-interactive
	// leaves present, which is the shape a swap lockup carries.
	sdkV2EncodedTapTree = "01c06082012088a9148739f40ec4dbf569dcb38134c6e7310908566981876920466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ad204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac01c066204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaad20466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ad204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac01c04902e803b175204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaad204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac01c04282012088a9148739f40ec4dbf569dcb38134c6e731090856698187690164b27520466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ac01c0480166b275204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaad20466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ac01c0260167b275204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac01c06082012088a9148739f40ec4dbf569dcb38134c6e73109085669818769204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ad206869b74af65ca55c1c6d1602e07751c4a0118dc08f8cdadd322eef787c457b14ac01c066204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ad20466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27ad209e0ee8da25ef252f6d6a1f2acd71025493f5640f4ddbf686c804acb91e7c0a3dac"
	sdkV2PkScript       = "512082bdca8aace6ba5eebf6db1fc9675637af48b2d0a5cbb637a671e672a12e41a7"
	// The leaf this bot must find: nonInteractiveClaim.
	sdkV2NonInteractiveClaimLeaf = "82012088a9148739f40ec4dbf569dcb38134c6e73109085669818769204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ad206869b74af65ca55c1c6d1602e07751c4a0118dc08f8cdadd322eef787c457b14ac"
	// The receiver nonInteractiveClaim is pinned to, i.e. what enforcePayTo wraps.
	sdkV2ReceiverPkScript = "51201b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
)

// Walks a real VHTLC.ScriptV2 taptree through the same steps
// claimer.matchOutput does, so a divergence from the SDK fails here rather
// than as a claim that never happens.
func TestRealSDKV2TaptreeIsClaimable(t *testing.T) {
	server := fixedPub(t, strings.Repeat("02", 32))
	emulator := fixedPub(t, strings.Repeat("03", 32))
	preimg := bytes.Repeat([]byte{0x42}, preimageSize)

	receiverPkScript, err := hex.DecodeString(sdkV2ReceiverPkScript)
	require.NoError(t, err)
	encoded, err := hex.DecodeString(sdkV2EncodedTapTree)
	require.NoError(t, err)

	scripts, err := txutils.DecodeTapTree(encoded)
	require.NoError(t, err)
	require.Len(t, scripts, 8)

	vs := &script.TapscriptsVtxoScript{}
	require.NoError(t, vs.Decode(scripts), "every v2 leaf must parse, not just the one we spend")
	require.Len(t, vs.Closures, 8)

	tapKey, _, err := vs.TapTree()
	require.NoError(t, err)
	derived, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	assert.Equal(t, sdkV2PkScript, hex.EncodeToString(derived),
		"taptree must derive the address the SDK funds")

	arkadeScript, err := EnforcePayTo(receiverPkScript)
	require.NoError(t, err)
	closure, err := findClaimClosure(
		vs, server, emulatorTweakedKey(arkadeScript, emulator), preimg,
	)
	require.NoError(t, err)

	revealed, err := closure.Script()
	require.NoError(t, err)
	assert.Equal(t, sdkV2NonInteractiveClaimLeaf, hex.EncodeToString(revealed))
}

// A v2 taptree holds TWO ConditionMultisigClosures carrying the same preimage
// condition: the collaborative claim (receiver + server) and
// nonInteractiveClaim (server + emulator). Only the second is ours, and the
// condition alone does not tell them apart — the key set does.
func TestRealSDKV2TaptreeHasTwoPreimageClosures(t *testing.T) {
	encoded, err := hex.DecodeString(sdkV2EncodedTapTree)
	require.NoError(t, err)
	scripts, err := txutils.DecodeTapTree(encoded)
	require.NoError(t, err)
	vs := &script.TapscriptsVtxoScript{}
	require.NoError(t, vs.Decode(scripts))

	expected, err := preimageCondition(
		mustDecodeHex(t, "8739f40ec4dbf569dcb38134c6e7310908566981"),
	)
	require.NoError(t, err)

	var matching int
	for _, c := range vs.Closures {
		cmc, ok := c.(*script.ConditionMultisigClosure)
		if !ok {
			continue
		}
		if bytes.Equal(cmc.Condition, expected) {
			matching++
		}
	}
	assert.Equal(t, 2, matching,
		"if this drops to 1 the SDK changed the leaf ladder; if the condition stops matching, it changed the script version")
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	return raw
}
