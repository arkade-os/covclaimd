package preimage

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
)

func EnforcePayTo(receiverPkScript []byte) ([]byte, error) {
	witnessProgram, err := p2trWitnessProgram(receiverPkScript)
	if err != nil {
		return nil, fmt.Errorf("invalid receiver pkScript: %w", err)
	}

	b := txscript.NewScriptBuilder()
	b.AddOp(arkade.OP_PUSHCURRENTINPUTINDEX)
	b.AddOp(arkade.OP_DUP)
	b.AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
	b.AddOp(arkade.OP_1)
	b.AddOp(arkade.OP_EQUALVERIFY)
	b.AddData(witnessProgram)
	b.AddOp(arkade.OP_EQUALVERIFY)
	b.AddOp(arkade.OP_INSPECTOUTPUTVALUE)
	b.AddOp(arkade.OP_PUSHCURRENTINPUTINDEX)
	b.AddOp(arkade.OP_INSPECTINPUTVALUE)
	b.AddOp(arkade.OP_GREATERTHANOREQUAL)
	return b.Script()
}

func CovenantClaimClosure(
	preimageHash []byte,
	receiverPkScript []byte,
	serverPubKey, emulatorPubKey *btcec.PublicKey,
) (script.Closure, error) {
	if serverPubKey == nil {
		return nil, fmt.Errorf("server pubkey must not be nil")
	}
	if emulatorPubKey == nil {
		return nil, fmt.Errorf("emulator pubkey must not be nil")
	}
	enforcement, err := EnforcePayTo(receiverPkScript)
	if err != nil {
		return nil, err
	}
	condition, err := preimageCondition(preimageHash)
	if err != nil {
		return nil, err
	}
	return &script.ConditionMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{
				serverPubKey,
				emulatorTweakedKey(enforcement, emulatorPubKey),
			},
		},
		Condition: condition,
	}, nil
}

func ValidateArkadeScript(arkadeScript []byte) ([]byte, error) {
	receiver, err := parseReceiverFromArkadeScript(arkadeScript)
	if err != nil {
		return nil, err
	}
	expected, err := EnforcePayTo(receiver)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(arkadeScript, expected) {
		return nil, fmt.Errorf("unsupported arkade_script shape: only EnforcePayTo is accepted in v1")
	}
	return receiver, nil
}

func p2trWitnessProgram(pkScript []byte) ([]byte, error) {
	if len(pkScript) != 34 {
		return nil, fmt.Errorf("expected 34-byte P2TR pkScript, got %d", len(pkScript))
	}
	if pkScript[0] != txscript.OP_1 || pkScript[1] != txscript.OP_DATA_32 {
		return nil, fmt.Errorf("not a P2TR script: prefix %02x %02x", pkScript[0], pkScript[1])
	}
	return pkScript[2:], nil
}

func preimageCondition(preimageHash []byte) ([]byte, error) {
	if len(preimageHash) != 20 {
		return nil, fmt.Errorf("expected 20-byte HASH160, got %d", len(preimageHash))
	}
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUAL).
		Script()
}

func emulatorTweakedKey(arkadeScript []byte, emulatorPubKey *btcec.PublicKey) *btcec.PublicKey {
	return arkade.ComputeArkadeScriptPublicKey(
		emulatorPubKey, arkade.ArkadeScriptHash(arkadeScript),
	)
}

func parseReceiverFromArkadeScript(arkadeScript []byte) ([]byte, error) {
	if len(arkadeScript) == 0 {
		return nil, fmt.Errorf("empty arkade_script")
	}
	tokenizer := txscript.MakeScriptTokenizer(0, arkadeScript)
	var witnessPrograms [][]byte
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_DATA_32 {
			witnessPrograms = append(witnessPrograms, tokenizer.Data())
		}
	}
	if err := tokenizer.Err(); err != nil {
		return nil, fmt.Errorf("tokenize arkade_script: %w", err)
	}
	if len(witnessPrograms) == 0 {
		return nil, fmt.Errorf("arkade_script contains no OP_DATA_32 push (no receiver witness program)")
	}
	if len(witnessPrograms) > 1 {
		return nil, fmt.Errorf("arkade_script contains %d OP_DATA_32 pushes; expected exactly 1", len(witnessPrograms))
	}
	receiver := make([]byte, 0, 34)
	receiver = append(receiver, txscript.OP_1, txscript.OP_DATA_32)
	receiver = append(receiver, witnessPrograms[0]...)
	return receiver, nil
}
