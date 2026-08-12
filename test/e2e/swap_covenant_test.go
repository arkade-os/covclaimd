package e2e_test

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"

	"github.com/arkade-os/covclaimd/pkg/preimage"
)

const (
	swapRefundLocktime = arklib.AbsoluteLocktime(1_800_000_000)
	swapAmount         = uint64(10_000)
)

var swapClaimDelay = arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 4096}

func TestSwapCovenantAsIsNotClaimable(t *testing.T) {
	ctx := t.Context()

	emulator := newEmulatorClient(t)
	emulatorPub := fetchIntroPubkey(t, emulator)

	maker := setupArkClient(t)
	faucetOffchain(t, maker, 0.001)

	bot := dialPreimageClient(t)
	covclaimdPub := fetchCovclaimdPubKey(t, bot)

	cfgData, err := maker.GetConfigData(ctx)
	require.NoError(t, err)

	providerPub, providerPkScript := freshTaprootKey(t)
	refundPkScript := freshTaprootPkScript(t)
	preimg := freshPreimage(t)

	closures := swapCovenantClosures(
		t, preimg, providerPub, cfgData.SignerPubKey, emulatorPub, refundPkScript,
	)

	arkadeScript, err := preimage.EnforcePayTo(providerPkScript)
	require.NoError(t, err)
	tapscripts, addr, encodedTapTree, pkScript := encodeVtxoScript(
		t, closures, cfgData.SignerPubKey, cfgData.Network,
	)

	_, _, err = preimage.BuildClaim(&preimage.MatchedClaim{
		Outpoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
		Amount:   swapAmount,
		Credentials: preimage.ClaimCredentials{
			Preimage:     preimg,
			ArkadeScript: arkadeScript,
			Taptree:      tapscripts,
			PkScript:     pkScript,
		},
	}, cfgData.CheckpointExitPath(), cfgData.SignerPubKey, emulatorPub)
	require.ErrorContains(t, err, "find claim closure",
		"the lightning-swap-service covenant carries no closure covclaimd can spend")

	pkt, err := preimage.BuildPacket(preimg, covclaimdPub, providerPkScript)
	require.NoError(t, err)

	sendOffChainToVHTLC(t, maker, addr, swapAmount, encodedTapTree, pkt)

	time.Sleep(15 * time.Second)
	require.Empty(t, vtxosForScript(t, ctx, maker, providerPkScript),
		"covclaimd must not claim the swap covenant as it stands today")
}

func TestSwapCovenantWithCovclaimdLeafIsClaimable(t *testing.T) {
	ctx := t.Context()

	emulator := newEmulatorClient(t)
	emulatorPub := fetchIntroPubkey(t, emulator)

	maker := setupArkClient(t)
	faucetOffchain(t, maker, 0.001)

	bot := dialPreimageClient(t)
	covclaimdPub := fetchCovclaimdPubKey(t, bot)

	cfgData, err := maker.GetConfigData(ctx)
	require.NoError(t, err)

	providerPub, providerPkScript := freshTaprootKey(t)
	refundPkScript := freshTaprootPkScript(t)
	preimg := freshPreimage(t)

	closures := swapCovenantClosures(
		t, preimg, providerPub, cfgData.SignerPubKey, emulatorPub, refundPkScript,
	)
	covclaimdLeaf, err := preimage.CovenantClaimClosure(
		btcutil.Hash160(preimg), providerPkScript, cfgData.SignerPubKey, emulatorPub,
	)
	require.NoError(t, err)
	closures = append(closures, covclaimdLeaf)

	_, addr, encodedTapTree, _ := encodeVtxoScript(
		t, closures, cfgData.SignerPubKey, cfgData.Network,
	)

	pkt, err := preimage.BuildPacket(preimg, covclaimdPub, providerPkScript)
	require.NoError(t, err)

	sendOffChainToVHTLC(t, maker, addr, swapAmount, encodedTapTree, pkt)

	v := pollForVtxoAt(t, ctx, maker.Indexer(), providerPkScript, 30*time.Second)
	require.Equal(t, swapAmount, v.Amount, "provider should be paid the full input value")
}

func swapCovenantClosures(
	t *testing.T,
	preimg []byte,
	receiverPub, serverPub, emulatorPub *btcec.PublicKey,
	refundPkScript []byte,
) []script.Closure {
	t.Helper()

	condition := swapPreimageCondition(t, btcutil.Hash160(preimg))

	refundArkadeScript, err := preimage.EnforcePayTo(refundPkScript)
	require.NoError(t, err)
	refundCosigner := arkade.ComputeArkadeScriptPublicKey(
		emulatorPub, arkade.ArkadeScriptHash(refundArkadeScript),
	)

	return []script.Closure{
		&script.ConditionMultisigClosure{
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{receiverPub, serverPub},
			},
			Condition: condition,
		},
		&script.CLTVMultisigClosure{
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{serverPub, refundCosigner},
			},
			Locktime: swapRefundLocktime,
		},
		&script.ConditionCSVMultisigClosure{
			CSVMultisigClosure: script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{receiverPub},
				},
				Locktime: swapClaimDelay,
			},
			Condition: condition,
		},
	}
}

func swapPreimageCondition(t *testing.T, preimageHash []byte) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)
	return s
}

func encodeVtxoScript(
	t *testing.T,
	closures []script.Closure,
	serverPub *btcec.PublicKey,
	network arklib.Network,
) ([]string, string, []byte, []byte) {
	t.Helper()

	vs := &script.TapscriptsVtxoScript{Closures: closures}
	tapscripts, err := vs.Encode()
	require.NoError(t, err)
	tapKey, _, err := vs.TapTree()
	require.NoError(t, err)
	encodedTapTree, err := txutils.TapTree(tapscripts).Encode()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	addr, err := (&arklib.Address{
		HRP:        network.Addr,
		Signer:     serverPub,
		VtxoTapKey: tapKey,
	}).EncodeV0()
	require.NoError(t, err)

	return tapscripts, addr, encodedTapTree, pkScript
}

func freshTaprootKey(t *testing.T) (*btcec.PublicKey, []byte) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pkScript, err := txscript.PayToTaprootScript(priv.PubKey())
	require.NoError(t, err)
	return priv.PubKey(), pkScript
}
