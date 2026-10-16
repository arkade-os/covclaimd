package preimage

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sdkV2Lockup struct {
	claimer      *claimer
	tx           *psbt.Packet
	preimage     []byte
	arkadeScript []byte
	taptree      []string
}

// One output per value, each paying the real SDK v2 lockup from vhtlc_v2_test.go.
func fundSDKV2Lockup(t *testing.T, values ...int64) sdkV2Lockup {
	t.Helper()
	secret, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x22}, 32))
	c := &claimer{
		cfg: Config{
			SecretKey:      secret,
			SignerPubKey:   fixedPub(t, strings.Repeat("02", 32)),
			EmulatorPubKey: fixedPub(t, strings.Repeat("03", 32)),
		},
		log: logrus.New(),
	}
	encoded := mustDecodeHex(t, sdkV2EncodedTapTree)
	taptree, err := txutils.DecodeTapTree(encoded)
	require.NoError(t, err)
	arkadeScript, err := EnforcePayTo(mustDecodeHex(t, sdkV2ReceiverPkScript))
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	for _, v := range values {
		tx.AddTxOut(wire.NewTxOut(v, mustDecodeHex(t, sdkV2PkScript)))
	}
	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	for i := range pkt.Outputs {
		pkt.Outputs[i].TaprootTapTree = encoded
	}
	return sdkV2Lockup{
		claimer:      c,
		tx:           pkt,
		preimage:     bytes.Repeat([]byte{0x42}, preimageSize),
		arkadeScript: arkadeScript,
		taptree:      taptree,
	}
}

func TestMatchOutput_DeclinesAnOutputBelowTheMinAmount(t *testing.T) {
	l := fundSDKV2Lockup(t, 49_999)
	minAmount := uint64(50_000)
	pkt := &ClaimPacket{ArkadeScript: l.arkadeScript, MinAmount: &minAmount}
	tweaked := emulatorTweakedKey(l.arkadeScript, l.claimer.cfg.EmulatorPubKey)

	_, ok := l.claimer.matchOutput(l.tx, 0, pkt, l.preimage, tweaked)
	assert.False(t, ok)

	l.tx.UnsignedTx.TxOut[0].Value = 50_000
	m, ok := l.claimer.matchOutput(l.tx, 0, pkt, l.preimage, tweaked)
	require.True(t, ok)
	assert.Equal(t, uint64(50_000), m.Amount)
}

func TestMatchRegistered_SkipsAnOutputBelowTheMinAmount(t *testing.T) {
	minAmount := uint64(50_000)
	register := func(l sdkV2Lockup) *RevealPlugin {
		ct, err := EncryptWithAAD(
			l.claimer.cfg.SecretKey.PubKey(), l.preimage, binary.BigEndian.AppendUint64(nil, minAmount),
		)
		require.NoError(t, err)
		return &RevealPlugin{claimer: l.claimer, packets: map[string]registration{
			sdkV2PkScript: {
				packet:   ClaimPacket{Ciphertext: ct, ArkadeScript: l.arkadeScript, MinAmount: &minAmount},
				taptree:  l.taptree,
				expireAt: time.Now().Add(time.Minute),
			},
		}}
	}

	dustOnly := fundSDKV2Lockup(t, 1_000)
	_, ok := register(dustOnly).matchRegistered(dustOnly.tx)
	assert.False(t, ok)

	dustThenFull := fundSDKV2Lockup(t, 1_000, 50_000)
	m, ok := register(dustThenFull).matchRegistered(dustThenFull.tx)
	require.True(t, ok)
	assert.Equal(t, uint32(1), m.Outpoint.Index)
	assert.Equal(t, uint64(50_000), m.Amount)
	assert.Equal(t, sdkV2PkScript, hex.EncodeToString(m.Credentials.PkScript))
}
