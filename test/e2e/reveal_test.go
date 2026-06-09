package e2e_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
	"github.com/arkade-os/covclaimd/pkg/preimage"
)

func dialRevealClient(t *testing.T) covclaimdv1.RevealServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(e2eGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return covclaimdv1.NewRevealServiceClient(conn)
}

// TestRevealFundAndClaim: maker reveals {swap_address, packet} to the bot over
// gRPC (NOT on-chain), then funds the VHTLC with no OP_RETURN packet. The bot
// must observe the funding tx, look up the registration, claim by revealing the
// preimage, and pay receiverPk.
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

	// Extract the ClaimPacket fields to send over RevealService.
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
	// Fund WITHOUT the on-chain packet — the reveal path supplies it.
	sendOffChainToVHTLC(t, maker, claimAddr, amount, encodedTapTree, nil)

	v := pollForVtxoAt(t, ctx, maker.Indexer(), receiverPk, 30*time.Second)
	require.Equal(t, amount, v.Amount, "receiver should be paid the full input value via the reveal path")
}

// TestRevealInvalidArkadeScriptRejected: a reveal with a tampered arkade script
// must be rejected at submit time (no funding needed).
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
			ArkadeScript: []byte{0xde, 0xad, 0xbe, 0xef}, // tampered
		},
	})
	require.Error(t, err, "tampered arkade script must be rejected at submit time")
}
