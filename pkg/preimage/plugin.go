package preimage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"

	"github.com/arkade-os/solver/pkg/executor"
)

type Config struct {
	Indexer  indexer.Indexer
	Emulator emulatorclient.TransportClient
	// The secret key used to encrypt and decrypt the packet data encoding the preimage to reveal
	SecretKey *btcec.PrivateKey

	EmulatorPubKey      *btcec.PublicKey
	SignerPubKey        *btcec.PublicKey
	CheckpointTapscript []byte
	Log                 logrus.FieldLogger
}

// NewPlugin builds the preimage executor.Plugin. The plugin implements the
// executor.Plugin contract directly: Match decodes a claim and gates it on vtxo
// spendability, Solve builds and submits the claim transaction.
func NewPlugin(_ context.Context, cfg Config) (executor.Plugin, error) {
	if cfg.Indexer == nil {
		return nil, fmt.Errorf("indexer client must not be nil")
	}
	if cfg.Emulator == nil {
		return nil, fmt.Errorf("emulator client must not be nil")
	}
	if cfg.SecretKey == nil {
		return nil, fmt.Errorf("covclaimd privkey must not be nil")
	}
	if cfg.EmulatorPubKey == nil {
		return nil, fmt.Errorf("emulator pubkey must not be nil")
	}
	if cfg.SignerPubKey == nil {
		return nil, fmt.Errorf("server pubkey must not be nil")
	}
	if len(cfg.CheckpointTapscript) == 0 {
		return nil, fmt.Errorf("checkpoint tapscript must not be empty")
	}
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}

	return &plugin{cfg, cfg.Log}, nil
}

type plugin struct {
	cfg Config
	log logrus.FieldLogger
}

// Filter applies no server-side CEL filter: the preimage plugin inspects the
// full tx stream and decides structurally in Match.
func (p *plugin) Filter() string { return "" }

// Match decodes a preimage claim from tx and confirms the funded vtxo is still
// spendable. It returns (claim, true) only when the tx carries a claim packet
// addressed to this covclaimd and the matching output is unspent; every other
// case is a silent miss.
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

	spendable, err := p.vtxoSpendable(ctx, claim)
	if err != nil {
		p.log.WithError(err).Debug("preimage vtxo spendable check failed")
		return nil, false
	}
	if !spendable {
		return nil, false
	}

	return claim, true
}

// Solve builds and submits the claim transaction for a matched intent.
func (p *plugin) Solve(ctx context.Context, intent any) {
	claim, ok := intent.(*MatchedClaim)
	if !ok {
		return
	}
	if err := p.claim(ctx, claim); err != nil {
		p.log.Error(err)
	}
}

// decode extracts a preimage claim from the parsed extension and the matching
// tx output. It returns ok=false (a silent miss) whenever the tx is not a
// well-formed claim addressed to this covclaimd.
func (p *plugin) decode(tx *psbt.Packet, ext extension.Extension) (*MatchedClaim, bool) {
	pkt, err := FindClaim(ext)
	if err != nil {
		p.log.WithError(err).Debug("preimage extension parse failed")
		return nil, false
	}
	if pkt == nil {
		return nil, false
	}

	preimg, err := Decrypt(p.cfg.SecretKey, pkt.Ciphertext)
	if err != nil {
		p.log.WithError(err).Debug("preimage decrypt failed")
		return nil, false
	}
	if len(preimg) != 32 {
		p.log.Debugf("decrypted preimage has wrong length %d (want 32)", len(preimg))
		return nil, false
	}
	if _, err := ValidateArkadeScript(pkt.ArkadeScript); err != nil {
		p.log.WithError(err).Debug("preimage arkade script invalid")
		return nil, false
	}
	expectedTweaked := emulatorTweakedKey(pkt.ArkadeScript, p.cfg.EmulatorPubKey)

	for i, out := range tx.UnsignedTx.TxOut {
		if i >= len(tx.Outputs) {
			break
		}
		po := tx.Outputs[i]
		if len(po.TaprootTapTree) == 0 {
			continue
		}

		scripts, err := txutils.DecodeTapTree(po.TaprootTapTree)
		if err != nil {
			p.log.WithError(err).Debug("preimage taptree decode failed")
			continue
		}

		vs := &script.TapscriptsVtxoScript{}
		if err := vs.Decode(scripts); err != nil {
			p.log.WithError(err).Debug("preimage taptree.Decode failed")
			continue
		}
		if _, err := findClaimClosure(vs, p.cfg.SignerPubKey, expectedTweaked); err != nil {
			continue
		}
		tapKey, _, err := vs.TapTree()
		if err != nil {
			continue
		}
		expectedPk, err := script.P2TRScript(tapKey)
		if err != nil {
			continue
		}
		if !bytes.Equal(out.PkScript, expectedPk) {
			continue
		}

		return &MatchedClaim{
			Outpoint: wire.OutPoint{Hash: tx.UnsignedTx.TxHash(), Index: uint32(i)},
			Amount:   uint64(out.Value),
			Credentials: ClaimCredentials{
				Preimage:     preimg,
				ArkadeScript: pkt.ArkadeScript,
				Taptree:      scripts,
				PkScript:     expectedPk,
			},
		}, true
	}
	return nil, false
}

// vtxoSpendable reports whether the claim's target output is still an unspent
// vtxo according to the indexer.
func (p *plugin) vtxoSpendable(ctx context.Context, m *MatchedClaim) (bool, error) {
	resp, err := p.cfg.Indexer.GetVtxos(ctx,
		indexer.WithScripts([]string{hex.EncodeToString(m.Credentials.PkScript)}),
		indexer.WithSpendableOnly(),
	)
	if err != nil {
		return false, err
	}
	return len(resp.Vtxos) > 0, nil
}

func (p *plugin) claim(ctx context.Context, m *MatchedClaim) error {
	log := p.log.WithField("outpoint", m.Outpoint.String())

	log.WithField("amount", m.Amount).
		WithField("arkade_script_hex", hex.EncodeToString(m.Credentials.ArkadeScript)).
		WithField("pk_script_hex", hex.EncodeToString(m.Credentials.PkScript)).
		WithField("taptree_leaves", len(m.Credentials.Taptree)).
		WithField("preimage_len", len(m.Credentials.Preimage)).
		Debug("preimage claim: matched, building ark tx")

	arkTx, checkpoints, err := BuildClaim(
		m, p.cfg.CheckpointTapscript, p.cfg.SignerPubKey, p.cfg.EmulatorPubKey,
	)
	if err != nil {
		return err
	}

	arkTxB64, err := arkTx.B64Encode()
	if err != nil {
		return err
	}
	cpTxids := make([]string, len(checkpoints))
	cpB64 := make([]string, len(checkpoints))
	for i, cp := range checkpoints {
		cpTxids[i] = cp.UnsignedTx.TxHash().String()
		b64, err := cp.B64Encode()
		if err != nil {
			return err
		}
		cpB64[i] = b64
	}

	log.WithField("txid", arkTx.UnsignedTx.TxHash().String()).
		WithField("tx", arkTxB64).
		WithField("checkpoints", cpB64).
		Debug("claim transaction built, submitting")

	_, _, err = p.cfg.Emulator.SubmitTx(ctx, arkTxB64, cpB64)
	return err
}
