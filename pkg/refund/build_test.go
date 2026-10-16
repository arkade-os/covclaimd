package refund

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"testing"
)

// checkpointTapscriptFixture returns a syntactically valid CSV multisig
// closure script, standing in for arkd's real signer-unroll checkpoint
// script. offchain.BuildTxs only requires that this decodes as a
// CSVMultisigClosure; its content plays no other role in the assertions
// below.
func checkpointTapscriptFixture(t *testing.T) []byte {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	closure := &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{key.PubKey()}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}
	b, err := closure.Script()
	require.NoError(t, err)
	return b
}

// matchedRefundFromFixture builds a MatchedRefund straight off the canonical
// fixture, decoding the SERIALIZED taptree exactly as production does (see
// decodeTapTree's own comment) rather than reassembling one from the leaf
// list.
func matchedRefundFromFixture(t *testing.T, v fixture, amount uint64) *MatchedRefund {
	t.Helper()
	taptree, err := txutils.DecodeTapTree(mustDecodeHex(t, v.TapTree))
	require.NoError(t, err)

	return &MatchedRefund{
		Outpoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
		Amount:   amount,
		SourceTx: wire.NewMsgTx(3),
		Credentials: RefundCredentials{
			ArkadeScript: v.RefundArkadeScript(),
			Taptree:      taptree,
			PkScript:     mustDecodeHex(t, v.PkScript),
		},
	}
}

// The refund's whole point is that the output is not the caller's to choose:
// the covenant pins it to senderPkScript, and BuildRefund must pay exactly
// that, deriving it from ArkadeScript rather than trusting a value the caller
// could have gotten wrong (or forged).
func TestBuildRefund_PaysTheSenderPkScriptTheCovenantEnforces(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	arkTx, checkpoints, err := BuildRefund(
		matched, checkpointTapscriptFixture(t), v.ServerPubKey(), v.EmulatorPubKey(),
	)
	require.NoError(t, err)
	require.NotNil(t, arkTx)
	require.Len(t, checkpoints, 1)

	require.Len(t, arkTx.UnsignedTx.TxOut, 3, "sender output, emulator extension output, anchor")
	require.Equal(t, v.RefundSenderPkScript(), arkTx.UnsignedTx.TxOut[0].PkScript)
	require.Equal(t, int64(50_000), arkTx.UnsignedTx.TxOut[0].Value)
}

// BuildClaim sets ConditionWitnessField because a ConditionMultisigClosure's
// HASH160 check needs the preimage on the witness stack. The refund leaf is a
// plain CLTVMultisigClosure: arkd's verifier (ark-lib script/verify.go) only
// reads ConditionWitnessField for the Condition* closure variants, so setting
// it here would be dead weight signalling a condition that does not exist.
func TestBuildRefund_SetsNoConditionWitness(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	arkTx, _, err := BuildRefund(
		matched, checkpointTapscriptFixture(t), v.ServerPubKey(), v.EmulatorPubKey(),
	)
	require.NoError(t, err)

	fields, err := txutils.GetArkPsbtFields(arkTx, 0, txutils.ConditionWitnessField)
	require.NoError(t, err)
	require.Empty(t, fields)
}

// A malformed or malicious ArkadeScript must fail closed: BuildRefund derives
// the actual transaction output from it, so this is the same trust boundary
// preimage.BuildClaim enforces via ValidateArkadeScript on the claim side.
func TestBuildRefund_RejectsAnArkadeScriptThatIsNotEnforcePayTo(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)
	matched.Credentials.ArkadeScript = []byte{0x51} // OP_1: not an EnforcePayTo script

	_, _, err := BuildRefund(
		matched, checkpointTapscriptFixture(t), v.ServerPubKey(), v.EmulatorPubKey(),
	)
	require.Error(t, err)
}

// The taptree must actually carry the non-interactive refund-without-receiver
// leaf. Using the eight-leaf shape (fixture minus that one leaf) must fail
// loudly with FindRefundClosure's own error, not silently build a spend for
// some other leaf.
func TestBuildRefund_ErrorsWhenTheLeafIsAbsentFromTheTaptree(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)
	eightLeaves := v.Leaves.AllExceptNonInteractiveRefundWithoutReceiver()
	matched.Credentials.Taptree = eightLeaves

	_, _, err := BuildRefund(
		matched, checkpointTapscriptFixture(t), v.ServerPubKey(), v.EmulatorPubKey(),
	)
	require.ErrorContains(t, err, "no non-interactive refund-without-receiver leaf")
}

func TestBuildRefund_RejectsANilMatch(t *testing.T) {
	_, _, err := BuildRefund(nil, checkpointTapscriptFixture(t), nil, nil)
	require.Error(t, err)
}

func TestBuildRefund_RejectsAMissingSourceTx(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)
	matched.SourceTx = nil

	_, _, err := BuildRefund(
		matched, checkpointTapscriptFixture(t), v.ServerPubKey(), v.EmulatorPubKey(),
	)
	require.Error(t, err)
}
