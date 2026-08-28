package refund

import (
	"errors"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/covclaimd/pkg/preimage"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// RefundCredentials carries what BuildRefund needs to identify and spend the
// nonInteractiveRefundWithoutReceiver leaf. It is the refund-side twin of
// preimage.ClaimCredentials, minus a preimage: this leaf has no hash
// condition to satisfy, only the CLTV and the two signatures.
type RefundCredentials struct {
	// ArkadeScript is EnforcePayTo(senderPkScript) — the exact bytes the
	// cosigner key was tweaked with (design doc: "same covenant bytes" as
	// nonInteractiveRefund). Re-validated inside BuildRefund for the same
	// reason preimage.BuildClaim re-validates it on the claim side: the
	// output this function builds is derived FROM it, so a malformed or
	// malicious script must fail closed rather than be trusted blind.
	ArkadeScript []byte
	// Taptree is the vtxo's whole revealed taproot tree, one hex script per
	// leaf — the same shape ClaimCredentials.Taptree carries.
	Taptree []string
	// PkScript is the vtxo's own P2TR output script, used by Refunder to look
	// the vtxo up in the indexer before attempting a spend.
	PkScript []byte
}

// MatchedRefund is the refund-side twin of preimage.MatchedClaim: a specific,
// already-identified vtxo output ready to be spent, plus everything needed to
// rebuild and re-verify the spend path against it.
type MatchedRefund struct {
	Outpoint    wire.OutPoint
	Amount      uint64
	SourceTx    *wire.MsgTx
	Credentials RefundCredentials
}

// locateRefundClosure decodes creds.Taptree and returns both the decoded
// vtxo script and the matched non-interactive refund-without-receiver
// closure, re-deriving the expected cosigner key the same way the leaf
// itself was built. BuildRefund and Refunder's maturity pre-check both go
// through this instead of each finding the leaf their own way, so the two
// can never disagree about which closure is under consideration — in
// particular, Refunder reads Locktime straight off the *script.CLTVMultisigClosure
// this returns, never from a separately supplied parameter or from config,
// so there is no second copy of that value that could drift from the one the
// tapscript itself enforces.
func locateRefundClosure(
	creds RefundCredentials, serverPubKey, emulatorPubKey *btcec.PublicKey,
) (*script.TapscriptsVtxoScript, *script.CLTVMultisigClosure, error) {
	vtxoScript := &script.TapscriptsVtxoScript{}
	if err := vtxoScript.Decode(creds.Taptree); err != nil {
		return nil, nil, fmt.Errorf("decode taptree: %w", err)
	}
	expectedCosigner := arkade.ComputeArkadeScriptPublicKey(
		emulatorPubKey, arkade.ArkadeScriptHash(creds.ArkadeScript),
	)
	closure, err := FindRefundClosure(vtxoScript, serverPubKey, expectedCosigner)
	if err != nil {
		return nil, nil, err
	}
	return vtxoScript, closure, nil
}

// BuildRefund assembles the ark and checkpoint txs that spend the
// nonInteractiveRefundWithoutReceiver leaf, paying back to the sender
// pkScript the covenant enforces.
//
// It mirrors preimage.BuildClaim closely — same taptree decode, same merkle
// proof / control block derivation, same emulator extension packet, same
// PrevArkTx binding — because the two are the same shape for opposite
// beneficiaries (claim pays the receiver, this pays the sender). It reuses
// preimage.ValidateArkadeScript rather than re-implementing EnforcePayTo
// parsing: the design that added this leaf states its covenant bytes are
// byte-identical to nonInteractiveRefund's, which already uses this exact
// enforcement fragment, and a second hand-copy of it is exactly the class of
// divergence PR #4 shipped once already (the SDK moved the preimage
// condition's shape; covclaimd's own separate copy did not move with it, and
// the claim silently never happened).
//
// Unlike BuildClaim, no ConditionWitnessField is set. The closure here is a
// plain CLTVMultisigClosure (CHECKLOCKTIMEVERIFY + 2-of-2 CHECKSIG, no hash
// condition), and arkd's verifier only reads ConditionWitnessField for the
// Condition* closure variants (ark-lib script/verify.go) — setting it would
// be inert weight implying a condition this leaf does not have.
//
// BuildRefund itself still does not check whether the CLTV has matured —
// nothing here can make an immature spend valid, since the tapscript's own
// CHECKLOCKTIMEVERIFY is the real gate. Refunder.Refund is where a LOCAL
// maturity pre-check lives now (reading Locktime off the same closure this
// function locates, via locateRefundClosure): not because it changes
// correctness, but because failing loudly and locally beats an opaque
// rejection from downstream, and because a daemon that skips a known-immature
// leaf instead of hammering the emulator with it produces less noise. See
// Refunder.Refund's doc comment.
func BuildRefund(
	matched *MatchedRefund,
	checkpointTapscriptBytes []byte,
	serverPubKey, emulatorPubKey *btcec.PublicKey,
) (*psbt.Packet, []*psbt.Packet, error) {
	if matched == nil {
		return nil, nil, errors.New("matched is nil")
	}
	if matched.SourceTx == nil {
		return nil, nil, errors.New("matched has no source tx: cannot prove the refunded prevout to the emulator")
	}
	creds := matched.Credentials

	senderPkScript, err := preimage.ValidateArkadeScript(creds.ArkadeScript)
	if err != nil {
		return nil, nil, fmt.Errorf("re-validate arkade_script: %w", err)
	}

	vtxoScript, refundClosure, err := locateRefundClosure(creds, serverPubKey, emulatorPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("find refund closure: %w", err)
	}

	revealedScript, err := refundClosure.Script()
	if err != nil {
		return nil, nil, fmt.Errorf("encode closure script: %w", err)
	}

	_, tapTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, fmt.Errorf("compute taptree: %w", err)
	}
	leafHash := txscript.NewBaseTapLeaf(revealedScript).TapHash()
	merkleProof, err := tapTree.GetTaprootMerkleProof(leafHash)
	if err != nil {
		return nil, nil, fmt.Errorf("merkle proof: %w", err)
	}
	controlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("parse control block: %w", err)
	}

	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{
		Vin:     0,
		Script:  slices.Clone(creds.ArkadeScript),
		Witness: wire.TxWitness{},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build emulator packet: %w", err)
	}
	ext, err := extension.NewExtensionFromPackets(emulatorPacket)
	if err != nil {
		return nil, nil, fmt.Errorf("build extension: %w", err)
	}
	extTxOut, err := ext.TxOut()
	if err != nil {
		return nil, nil, fmt.Errorf("build extension TxOut: %w", err)
	}

	outputs := []*wire.TxOut{
		{Value: int64(matched.Amount), PkScript: senderPkScript},
		extTxOut,
	}

	vtxoInput := offchain.VtxoInput{
		Outpoint: &matched.Outpoint,
		Amount:   int64(matched.Amount),
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   controlBlock,
			RevealedScript: revealedScript,
		},
		RevealedTapscripts: slices.Clone(creds.Taptree),
	}

	arkTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput}, outputs, checkpointTapscriptBytes,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("build offchain txs: %w", err)
	}

	if err := txutils.SetArkPsbtField(
		arkTx, 0, arkade.PrevArkTxField, *matched.SourceTx,
	); err != nil {
		return nil, nil, fmt.Errorf("set prev ark tx on ark tx: %w", err)
	}

	return arkTx, checkpoints, nil
}
