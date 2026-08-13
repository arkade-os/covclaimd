package preimage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

type ClaimCredentials struct {
	Preimage     []byte
	ArkadeScript []byte
	Taptree      []string
	PkScript     []byte
}

type MatchedClaim struct {
	Outpoint wire.OutPoint
	Amount   uint64
	SourceTx    *wire.MsgTx
	Credentials ClaimCredentials
}

func BuildClaim(
	matched *MatchedClaim,
	checkpointTapscriptBytes []byte,
	signerPubKey, emulatorPubKey *btcec.PublicKey,
) (*psbt.Packet, []*psbt.Packet, error) {
	if matched == nil {
		return nil, nil, errors.New("matched is nil")
	}
	if matched.SourceTx == nil {
		return nil, nil, errors.New("matched has no source tx: cannot prove the claimed prevout to the emulator")
	}
	creds := matched.Credentials
	if len(creds.Preimage) != preimageSize {
		return nil, nil, fmt.Errorf(
			"preimage must be %d bytes, got %d", preimageSize, len(creds.Preimage),
		)
	}

	receiverPkScript, err := ValidateArkadeScript(creds.ArkadeScript)
	if err != nil {
		return nil, nil, fmt.Errorf("re-validate arkade_script: %w", err)
	}

	vtxoScript := &script.TapscriptsVtxoScript{}
	if err := vtxoScript.Decode(creds.Taptree); err != nil {
		return nil, nil, fmt.Errorf("decode taptree: %w", err)
	}
	expectedTweaked := emulatorTweakedKey(creds.ArkadeScript, emulatorPubKey)
	claimClosure, err := findClaimClosure(vtxoScript, signerPubKey, expectedTweaked, creds.Preimage)
	if err != nil {
		return nil, nil, fmt.Errorf("find claim closure: %w", err)
	}

	revealedScript, err := claimClosure.Script()
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
		{Value: int64(matched.Amount), PkScript: receiverPkScript},
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

	preimageWitness := wire.TxWitness{slices.Clone(creds.Preimage)}
	if err := txutils.SetArkPsbtField(
		arkTx, 0, txutils.ConditionWitnessField, preimageWitness,
	); err != nil {
		return nil, nil, fmt.Errorf("set condition witness on ark tx: %w", err)
	}
	for i, cp := range checkpoints {
		if err := txutils.SetArkPsbtField(
			cp, 0, txutils.ConditionWitnessField, preimageWitness,
		); err != nil {
			return nil, nil, fmt.Errorf("set condition witness on checkpoint %d: %w", i, err)
		}
	}

	return arkTx, checkpoints, nil
}

func findClaimClosure(
	vtxoScript *script.TapscriptsVtxoScript,
	serverPubKey, expectedTweaked *btcec.PublicKey,
	preimage []byte,
) (script.Closure, error) {
	expectedCondition, err := preimageCondition(btcutil.Hash160(preimage))
	if err != nil {
		return nil, err
	}
	// Counted as we go, so the failure can name which wall we hit rather than
	// the one message that used to cover all four. "No claim closure" is the
	// symptom of a wrong script version, a wrong preimage, and a misconfigured
	// signer key alike, and from the outside those looked identical.
	var conditionClosures, conditionMatches int
	for _, c := range vtxoScript.Closures {
		cmc, ok := c.(*script.ConditionMultisigClosure)
		if !ok {
			continue
		}
		conditionClosures++
		if !bytes.Equal(cmc.Condition, expectedCondition) {
			continue
		}
		conditionMatches++
		if hasExactlyTwoKeys(cmc.PubKeys, serverPubKey, expectedTweaked) {
			return cmc, nil
		}
	}

	switch {
	case conditionClosures == 0:
		return nil, fmt.Errorf(
			"taptree has %d closure(s) but no ConditionMultisigClosure: not a claimable contract shape",
			len(vtxoScript.Closures),
		)
	case conditionMatches == 0:
		return nil, fmt.Errorf(
			"none of %d ConditionMultisigClosure(s) commit to HASH160 of this preimage: wrong preimage, or a condition this version does not build",
			conditionClosures,
		)
	default:
		return nil, fmt.Errorf(
			"%d closure(s) match the preimage condition but none is a 2-of-2 of (server %s, emulator-tweaked %s): check the configured signer key and the arkade_script the tweak was derived from",
			conditionMatches,
			hex.EncodeToString(schnorr.SerializePubKey(serverPubKey)),
			hex.EncodeToString(schnorr.SerializePubKey(expectedTweaked)),
		)
	}
}

func hasExactlyTwoKeys(pubKeys []*btcec.PublicKey, a, b *btcec.PublicKey) bool {
	if len(pubKeys) != 2 {
		return false
	}
	wantA := schnorr.SerializePubKey(a)
	wantB := schnorr.SerializePubKey(b)
	k0 := schnorr.SerializePubKey(pubKeys[0])
	k1 := schnorr.SerializePubKey(pubKeys[1])
	return (bytes.Equal(k0, wantA) && bytes.Equal(k1, wantB)) ||
		(bytes.Equal(k0, wantB) && bytes.Equal(k1, wantA))
}
