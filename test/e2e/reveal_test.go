package e2e_test

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
	"github.com/arkade-os/covclaimd/pkg/preimage"
)

func TestRevealFundAndClaim(t *testing.T) {
	ctx := t.Context()

	emulator := newEmulatorClient(t)
	emulatorPub := fetchIntroPubkey(t, emulator)

	maker := setupArkClient(t)
	faucetOffchain(t, maker, 0.001)

	bot := dialPreimageClient(t)
	covclaimdPub := fetchCovclaimdPubKey(t, bot)
	reveal := dialRevealClient(t)

	cfgData, err := maker.GetConfigData(ctx)
	require.NoError(t, err)

	receiverPk := freshTaprootPkScript(t)
	preimg := freshPreimage(t)

	claimAddr, claimPacket, encodedTapTree := buildPreimageVTXO(
		t, preimg, receiverPk, covclaimdPub,
		cfgData.SignerPubKey, emulatorPub, cfgData.Network,
	)

	body, err := claimPacket.Serialize()
	require.NoError(t, err)
	pkt, err := preimage.DeserializeClaim(body)
	require.NoError(t, err)

	_, err = reveal.Reveal(ctx, &covclaimdv1.RevealRequest{
		SwapAddress: claimAddr,
		Packet: &covclaimdv1.ClaimPacket{
			Ciphertext:   pkt.Ciphertext,
			ArkadeScript: pkt.ArkadeScript,
		},
	})
	require.NoError(t, err, "reveal submission must be accepted")

	const amount uint64 = 10_000
	sendOffChainToVHTLC(t, maker, claimAddr, amount, encodedTapTree, nil)

	v := pollForVtxoAt(t, ctx, maker.Indexer(), receiverPk, 30*time.Second)
	require.Equal(t, amount, v.Amount, "receiver should be paid the full input value via the reveal path")
}

func TestRevealAfterFunding(t *testing.T) {
	ctx := t.Context()

	emulator := newEmulatorClient(t)
	emulatorPub := fetchIntroPubkey(t, emulator)

	maker := setupArkClient(t)
	faucetOffchain(t, maker, 0.001)

	bot := dialPreimageClient(t)
	covclaimdPub := fetchCovclaimdPubKey(t, bot)
	reveal := dialRevealClient(t)

	cfgData, err := maker.GetConfigData(ctx)
	require.NoError(t, err)

	receiverPk := freshTaprootPkScript(t)
	preimg := freshPreimage(t)

	claimAddr, claimPacket, encodedTapTree := buildPreimageVTXO(
		t, preimg, receiverPk, covclaimdPub,
		cfgData.SignerPubKey, emulatorPub, cfgData.Network,
	)

	const amount uint64 = 10_000
	sendOffChainToVHTLC(t, maker, claimAddr, amount, encodedTapTree, nil)

	vhtlcArk, err := arklib.DecodeAddressV0(claimAddr)
	require.NoError(t, err)
	vhtlcPkScript, err := script.P2TRScript(vhtlcArk.VtxoTapKey)
	require.NoError(t, err)
	pollForVtxoAt(t, ctx, maker.Indexer(), vhtlcPkScript, 30*time.Second)

	body, err := claimPacket.Serialize()
	require.NoError(t, err)
	pkt, err := preimage.DeserializeClaim(body)
	require.NoError(t, err)

	_, err = reveal.Reveal(ctx, &covclaimdv1.RevealRequest{
		SwapAddress: claimAddr,
		Packet: &covclaimdv1.ClaimPacket{
			Ciphertext:   pkt.Ciphertext,
			ArkadeScript: pkt.ArkadeScript,
		},
	})
	require.NoError(t, err, "reveal after funding must be accepted")

	v := pollForVtxoAt(t, ctx, maker.Indexer(), receiverPk, 30*time.Second)
	require.Equal(t, amount, v.Amount, "receiver should be paid even when the reveal arrives after funding")
}

func TestRevealInvalidArkadeScriptRejected(t *testing.T) {
	ctx := t.Context()

	emulator := newEmulatorClient(t)
	emulatorPub := fetchIntroPubkey(t, emulator)

	maker := setupArkClient(t)

	bot := dialPreimageClient(t)
	covclaimdPub := fetchCovclaimdPubKey(t, bot)
	reveal := dialRevealClient(t)

	cfgData, err := maker.GetConfigData(ctx)
	require.NoError(t, err)

	receiverPk := freshTaprootPkScript(t)
	preimg := freshPreimage(t)

	claimAddr, claimPacket, _ := buildPreimageVTXO(
		t, preimg, receiverPk, covclaimdPub,
		cfgData.SignerPubKey, emulatorPub, cfgData.Network,
	)
	body, err := claimPacket.Serialize()
	require.NoError(t, err)
	pkt, err := preimage.DeserializeClaim(body)
	require.NoError(t, err)

	_, err = reveal.Reveal(ctx, &covclaimdv1.RevealRequest{
		SwapAddress: claimAddr,
		Packet: &covclaimdv1.ClaimPacket{
			Ciphertext:   pkt.Ciphertext,
			ArkadeScript: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	})
	require.Error(t, err, "tampered arkade script must be rejected at submit time")
}

func dialRevealClient(t *testing.T) covclaimdv1.RevealServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(e2eGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return covclaimdv1.NewRevealServiceClient(conn)
}
