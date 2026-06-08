package preimage

import (
	"bytes"
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
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// MatchedClaim is the typed intent produced by the plugin's decode stage.
type MatchedClaim struct {
	Outpoint    wire.OutPoint
	Amount      uint64
	Credentials ClaimCredentials
}

// BuildClaim builds the unsigned ark tx + checkpoint(s) that spend a single
// preimage-gated VTXO. Pure CPU.
func BuildClaim(
	matched *MatchedClaim,
	checkpointTapscriptBytes []byte,
	signerPubKey, emulatorPubKey *btcec.PublicKey,
) (*psbt.Packet, []*psbt.Packet, error) {
	if matched == nil {
		return nil, nil, errors.New("matched is nil")
	}
	creds := matched.Credentials
	if len(creds.Preimage) == 0 {
		return nil, nil, errors.New("preimage is empty")
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
	claimClosure, err := findClaimClosure(vtxoScript, signerPubKey, expectedTweaked)
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
) (script.Closure, error) {
	for _, c := range vtxoScript.Closures {
		cmc, ok := c.(*script.ConditionMultisigClosure)
		if !ok {
			continue
		}
		if hasExactlyTwoKeys(cmc.PubKeys, serverPubKey, expectedTweaked) {
			return cmc, nil
		}
	}
	return nil, errors.New("no ConditionMultisigClosure with (serverPubKey, expectedTweaked) found in taptree")
}

// hasExactlyTwoKeys compares via x-only Schnorr serialization because closure
// pubkeys lose Y-parity across the encode/decode boundary.
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
