package refund

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// fixtureLeaves mirrors the fixture's "leaves" object: every individual leaf
// script, hex-encoded, keyed by name.
type fixtureLeaves struct {
	Claim                               string `json:"claim"`
	Refund                              string `json:"refund"`
	RefundWithoutReceiver               string `json:"refundWithoutReceiver"`
	UnilateralClaim                     string `json:"unilateralClaim"`
	UnilateralRefund                    string `json:"unilateralRefund"`
	UnilateralRefundWithoutReceiver     string `json:"unilateralRefundWithoutReceiver"`
	NonInteractiveClaim                 string `json:"nonInteractiveClaim"`
	NonInteractiveRefund                string `json:"nonInteractiveRefund"`
	NonInteractiveRefundWithoutReceiver string `json:"nonInteractiveRefundWithoutReceiver"`
}

// AllExceptNonInteractiveRefundWithoutReceiver returns the eight-leaf shape:
// every leaf the fixture carries except the one under test, in the fixture's
// own leaf order. Used to build a taptree where the leaf is genuinely absent,
// so FindRefundClosure's error path is exercised against real sibling leaves
// rather than an empty tree.
func (l fixtureLeaves) AllExceptNonInteractiveRefundWithoutReceiver() []string {
	return []string{
		l.Claim,
		l.Refund,
		l.RefundWithoutReceiver,
		l.UnilateralClaim,
		l.UnilateralRefund,
		l.UnilateralRefundWithoutReceiver,
		l.NonInteractiveClaim,
		l.NonInteractiveRefund,
	}
}

// fixtureJSON mirrors the on-disk shape of testdata/vhtlc-v2-nine-leaf.json.
// Only the fields this test needs are declared; encoding/json ignores the rest.
type fixtureJSON struct {
	Options struct {
		Server               string `json:"server"`
		NonInteractiveRefund struct {
			SenderPkScript string `json:"senderPkScript"`
			EmulatorPubkey string `json:"emulatorPubkey"`
		} `json:"nonInteractiveRefund"`
	} `json:"options"`
	TapTree       string        `json:"tapTree"`
	Leaves        fixtureLeaves `json:"leaves"`
	ArkadeScripts struct {
		NonInteractiveRefund string `json:"nonInteractiveRefund"`
	} `json:"arkadeScripts"`
}

// fixture is the parsed form of fixtureJSON, with the keys FindRefundClosure
// needs pre-derived at load time so callers don't have to thread errors
// through every accessor.
type fixture struct {
	TapTree string
	Leaves  fixtureLeaves

	serverPubKey         *btcec.PublicKey
	emulatorPubKey       *btcec.PublicKey
	refundCosigner       *btcec.PublicKey
	refundArkadeScript   []byte
	refundSenderPkScript []byte
}

// ServerPubKey returns the Arkade Service key the fixture was built with.
func (f fixture) ServerPubKey() *btcec.PublicKey { return f.serverPubKey }

// EmulatorPubKey returns the raw (untweaked) emulator key the fixture was
// built with — the second argument BuildRefund needs in order to re-derive
// RefundCosigner independently rather than being handed it directly.
func (f fixture) EmulatorPubKey() *btcec.PublicKey { return f.emulatorPubKey }

// RefundCosigner returns the covenant-tweaked emulator key that co-signs the
// non-interactive refund-without-receiver leaf alongside the server — the
// same derivation preimage.emulatorTweakedKey uses on the claim side:
// ComputeArkadeScriptPublicKey(emulatorPubKey, ArkadeScriptHash(arkadeScript)).
func (f fixture) RefundCosigner() *btcec.PublicKey { return f.refundCosigner }

// RefundArkadeScript returns EnforcePayTo(senderPkScript) — the exact bytes
// the cosigner key above is tweaked with, and the bytes BuildRefund must hand
// the emulator so it can verify the payout before co-signing.
func (f fixture) RefundArkadeScript() []byte { return f.refundArkadeScript }

// RefundSenderPkScript returns the pkScript the covenant enforces the refund
// pays to.
func (f fixture) RefundSenderPkScript() []byte { return f.refundSenderPkScript }

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	var j fixtureJSON
	require.NoError(t, json.Unmarshal(raw, &j))

	server := mustParsePubKey(t, j.Options.Server)
	emulator := mustParseXOnlyPubKey(t, j.Options.NonInteractiveRefund.EmulatorPubkey)
	arkadeScript := mustDecodeHex(t, j.ArkadeScripts.NonInteractiveRefund)
	senderPkScript := mustDecodeHex(t, j.Options.NonInteractiveRefund.SenderPkScript)
	cosigner := arkade.ComputeArkadeScriptPublicKey(emulator, arkade.ArkadeScriptHash(arkadeScript))

	return fixture{
		TapTree:              j.TapTree,
		Leaves:               j.Leaves,
		serverPubKey:         server,
		emulatorPubKey:       emulator,
		refundCosigner:       cosigner,
		refundArkadeScript:   arkadeScript,
		refundSenderPkScript: senderPkScript,
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	return raw
}

// mustParsePubKey parses a compressed (33-byte) secp256k1 pubkey, the shape
// the fixture uses for sender/receiver/server.
func mustParsePubKey(t *testing.T, s string) *btcec.PublicKey {
	t.Helper()
	pub, err := btcec.ParsePubKey(mustDecodeHex(t, s))
	require.NoError(t, err)
	return pub
}

// mustParseXOnlyPubKey parses a 32-byte x-only (BIP-340/schnorr) pubkey, the
// shape the fixture uses for the emulator key.
func mustParseXOnlyPubKey(t *testing.T, s string) *btcec.PublicKey {
	t.Helper()
	pub, err := schnorr.ParsePubKey(mustDecodeHex(t, s))
	require.NoError(t, err)
	return pub
}

// decodeTapTree decodes the SERIALIZED taptree blob, exactly as
// claimer.matchOutput does in production: txutils.DecodeTapTree followed by
// TapscriptsVtxoScript.Decode. This is deliberately not a tree reassembled
// from the leaf list — that would test our own reassembly rather than the
// SDK's bytes, which is precisely the gap that let the v1/v2 preimage
// condition divergence ship undetected.
func decodeTapTree(t *testing.T, tapTreeHex string) *script.TapscriptsVtxoScript {
	t.Helper()
	raw := mustDecodeHex(t, tapTreeHex)
	scripts, err := txutils.DecodeTapTree(raw)
	require.NoError(t, err)
	vs := &script.TapscriptsVtxoScript{}
	require.NoError(t, vs.Decode(scripts))
	return vs
}

// decodeLeaves builds a taptree straight from individual leaf hexes, used
// only to construct the eight-leaf shape (the fixture's serialized tapTree
// is always the nine-leaf one).
func decodeLeaves(t *testing.T, leaves []string) *script.TapscriptsVtxoScript {
	t.Helper()
	vs := &script.TapscriptsVtxoScript{}
	require.NoError(t, vs.Decode(leaves))
	return vs
}

func TestFindRefundClosure_PicksTheCovenantLeafNotTheSenderLeaf(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	// Decode the SERIALIZED taptree, exactly as claimer.matchOutput does in
	// production — not a tree reassembled from the leaf list, which would
	// test our own reassembly rather than the SDK's bytes.
	vtxo := decodeTapTree(t, v.TapTree)

	got, err := FindRefundClosure(vtxo, v.ServerPubKey(), v.RefundCosigner())
	require.NoError(t, err)

	revealed, err := got.Script()
	require.NoError(t, err)
	require.Equal(t, v.Leaves.NonInteractiveRefundWithoutReceiver, hex.EncodeToString(revealed))

	// The sender-signed twin has the same type and the same locktime.
	require.NotEqual(t, v.Leaves.RefundWithoutReceiver, hex.EncodeToString(revealed))
}

func TestFindRefundClosure_ErrorsWhenTheLeafIsAbsent(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	// The eight-leaf shape: same fixture, new leaf removed from the leaf list.
	// Built via TapscriptsVtxoScript.Decode over the eight leaf hexes, since
	// the fixture's serialized tapTree is the nine-leaf one.
	vtxo := decodeLeaves(t, v.Leaves.AllExceptNonInteractiveRefundWithoutReceiver())

	_, err := FindRefundClosure(vtxo, v.ServerPubKey(), v.RefundCosigner())
	require.ErrorContains(t, err, "no non-interactive refund-without-receiver leaf")
}

// TestFindRefundClosure_RejectsWrongCosignerEvenWhenServerMatches locks in the
// PubKeys[1] (cosigner) half of the comparison, which nothing above exercises.
// On this fixture, refundWithoutReceiver is [sender, server] and the target
// leaf is [server, cosigner], so sender != server already disambiguates at
// index 0 alone — a mutant that deleted the cosigner comparison and matched
// on PubKeys[0] == server alone would still pass every test above.
//
// This closure's first key IS the real server; its second is an unrelated
// key. If the cosigner check were missing, FindRefundClosure would return
// this closure. It must instead fall through to the not-found error.
func TestFindRefundClosure_RejectsWrongCosignerEvenWhenServerMatches(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")

	notCosigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxo := &script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.CLTVMultisigClosure{
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{v.ServerPubKey(), notCosigner.PubKey()},
			},
			Locktime: 1000,
		},
	}}

	_, err = FindRefundClosure(vtxo, v.ServerPubKey(), v.RefundCosigner())
	require.ErrorContains(t, err, "no non-interactive refund-without-receiver leaf")
}
