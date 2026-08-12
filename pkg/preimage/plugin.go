package preimage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/arkade-os/solver/pkg/executor"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Indexer             indexer.Indexer
	Emulator            emulatorclient.TransportClient
	SecretKey           *btcec.PrivateKey
	EmulatorPubKey      *btcec.PublicKey
	SignerPubKey        *btcec.PublicKey
	CheckpointTapscript []byte
	Log                 logrus.FieldLogger
}

func NewPlugin(_ context.Context, cfg Config) (executor.Plugin, error) {
	c, err := newClaimer(cfg)
	if err != nil {
		return nil, err
	}
	return &plugin{claimer: c, pubKey: cfg.SecretKey.PubKey().SerializeCompressed()}, nil
}

type plugin struct {
	*claimer
	// pubKey is the compressed key a packet must commit to for us to open it,
	// serialized once so neither Filter nor Match repeats the point multiply.
	pubKey []byte
}

// Filter selects, server-side, the txs whose Arkade extension carries a claim
// packet sealed to this covclaimd. arkd exposes tx.extension as a map of packet
// type to the hex of that packet's body, so the needle is the committed-key TLV
// exactly as it goes on the wire — written here by the same encoder that writes
// the packet, so the two cannot drift apart. Both sides hex-encode with
// encoding/hex, i.e. lowercase; a case mismatch would match nothing, silently.
//
// This is inert until arkdsource stops discarding it, and must stay inert until
// every emitter stamps the key: the expression selects on the 0x03 TLV, so
// turning it on while something still stamps the two-TLV shape would silently
// drop those packets. Deserialize accepts them; this deliberately would not.
//
// contains, not a fixed offset, because the wire format does not fix TLV order:
// a sender that emitted them in another order would still be addressing us, and
// dropping that packet would strand a swap. The asymmetry decides it — a false
// positive costs one TLV parse and a byte compare in Match, a false negative
// costs a claim.
func (p *plugin) Filter() string {
	needle := &bytes.Buffer{}
	encodeTLV(needle, tlvCovclaimdPubKey, p.pubKey)
	return fmt.Sprintf(
		"has(tx.extension) && hasPacket(tx.extension, %d) && tx.extension[%d].contains('%s')",
		PacketType, PacketType, hex.EncodeToString(needle.Bytes()),
	)
}

func (p *plugin) Match(ctx context.Context, tx *psbt.Packet) (any, bool) {
	if tx == nil || tx.UnsignedTx == nil {
		return nil, false
	}

	ext, err := extension.NewExtensionFromTx(tx.UnsignedTx)
	if err != nil {
		if !errors.Is(err, extension.ErrExtensionNotFound) {
			p.log.WithError(err).Debug("preimage extension parse failed")
		}
		return nil, false
	}

	claim, ok := p.decode(tx, ext)
	if !ok {
		return nil, false
	}
	return p.gateSpendable(ctx, claim)
}

func (p *plugin) Solve(ctx context.Context, intent any) {
	claim, ok := intent.(*MatchedClaim)
	if !ok {
		return
	}
	if err := p.claim(ctx, claim); err != nil {
		p.log.Error(err)
	}
}

func (p *plugin) decode(tx *psbt.Packet, ext extension.Extension) (*MatchedClaim, bool) {
	pkt, err := FindClaim(ext)
	if err != nil {
		p.log.WithError(err).Debug("preimage extension parse failed")
		return nil, false
	}
	if pkt == nil {
		return nil, false
	}
	// Before ECDH and AES-GCM, and before any of the taptree work: is this
	// packet even ours? The stream carries every covclaimd's packets, and
	// nothing upstream of here has to be trusted for this to be sound —
	// getting it wrong only means we try to decrypt something we can't.
	//
	// A packet that names no covclaimd at all is not declined — see
	// SealedToAnother. Only one that names someone else is dropped here.
	if pkt.SealedToAnother(p.pubKey) {
		p.log.WithField("sealed_to", hex.EncodeToString(pkt.CovclaimdPubKey)).
			Debug("preimage packet sealed to another covclaimd")
		return nil, false
	}
	preimg, ok := p.decodePacket(pkt)
	if !ok {
		return nil, false
	}
	expectedTweaked := emulatorTweakedKey(pkt.ArkadeScript, p.cfg.EmulatorPubKey)
	for i := range tx.UnsignedTx.TxOut {
		if m, ok := p.matchOutput(tx, i, pkt, preimg, expectedTweaked); ok {
			return m, true
		}
	}
	return nil, false
}
