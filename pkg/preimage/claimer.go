package preimage

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

type claimer struct {
	cfg Config
	log logrus.FieldLogger
}

func newClaimer(cfg Config) (*claimer, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	return &claimer{cfg: cfg, log: cfg.Log}, nil
}

func (c *claimer) decodePacket(pkt *ClaimPacket) ([]byte, bool) {
	preimg, err := pkt.Decrypt(c.cfg.SecretKey)
	if err != nil {
		c.log.WithError(err).Debug("preimage packet validation failed")
		return nil, false
	}
	return preimg, true
}

func (c *claimer) matchOutput(tx *psbt.Packet, i int, pkt *ClaimPacket, preimg []byte, expectedTweaked *btcec.PublicKey) (*MatchedClaim, bool) {
	if i >= len(tx.UnsignedTx.TxOut) || i >= len(tx.Outputs) {
		return nil, false
	}
	out := tx.UnsignedTx.TxOut[i]
	po := tx.Outputs[i]
	if len(po.TaprootTapTree) == 0 {
		c.log.WithField("vout", i).Debug("preimage output carries no taptree")
		return nil, false
	}

	scripts, err := txutils.DecodeTapTree(po.TaprootTapTree)
	if err != nil {
		c.log.WithError(err).Debug("preimage taptree decode failed")
		return nil, false
	}
	vs := &script.TapscriptsVtxoScript{}
	if err := vs.Decode(scripts); err != nil {
		c.log.WithError(err).Debug("preimage taptree.Decode failed")
		return nil, false
	}
	// Every decline below is correct. Declining SILENTLY is not: this is the
	// last thing standing between a revealed preimage and a claim, and when it
	// says nothing the only way to find out why is to read this function.
	log := c.log.WithField("vout", i)
	if _, err := findClaimClosure(vs, c.cfg.SignerPubKey, expectedTweaked, preimg); err != nil {
		log.WithError(err).Debug("preimage claim closure not found")
		return nil, false
	}
	tapKey, _, err := vs.TapTree()
	if err != nil {
		log.WithError(err).Debug("preimage taptree key derivation failed")
		return nil, false
	}
	expectedPk, err := script.P2TRScript(tapKey)
	if err != nil {
		log.WithError(err).Debug("preimage P2TR script build failed")
		return nil, false
	}
	if !bytes.Equal(out.PkScript, expectedPk) {
		// The taptree parses and holds our claim leaf, but the output was not
		// funded to the key it derives — so both scripts are worth having.
		log.WithFields(logrus.Fields{
			"output_pkscript":  hex.EncodeToString(out.PkScript),
			"derived_pkscript": hex.EncodeToString(expectedPk),
		}).Debug("preimage taptree does not derive this output's pkScript")
		return nil, false
	}

	return &MatchedClaim{
		Outpoint: wire.OutPoint{Hash: tx.UnsignedTx.TxHash(), Index: uint32(i)},
		Amount:   uint64(out.Value),
		SourceTx: tx.UnsignedTx.Copy(),
		Credentials: ClaimCredentials{
			Preimage:     preimg,
			ArkadeScript: pkt.ArkadeScript,
			Taptree:      scripts,
			PkScript:     expectedPk,
		},
	}, true
}

func (c *claimer) gateSpendable(ctx context.Context, m *MatchedClaim) (any, bool) {
	resp, err := c.cfg.Indexer.GetVtxos(ctx,
		indexer.WithScripts([]string{hex.EncodeToString(m.Credentials.PkScript)}),
		indexer.WithSpendableOnly(),
	)
	if err != nil {
		c.log.WithError(err).Debug("vtxo spendable check failed")
		return nil, false
	}
	if len(resp.Vtxos) == 0 {
		return nil, false
	}
	return m, true
}

func (c *claimer) claim(ctx context.Context, m *MatchedClaim) error {
	log := c.log.WithField("outpoint", m.Outpoint.String())

	log.WithField("amount", m.Amount).
		WithField("arkade_script_hex", hex.EncodeToString(m.Credentials.ArkadeScript)).
		WithField("pk_script_hex", hex.EncodeToString(m.Credentials.PkScript)).
		WithField("taptree_leaves", len(m.Credentials.Taptree)).
		WithField("preimage_len", len(m.Credentials.Preimage)).
		Debug("preimage claim: matched, building ark tx")

	arkTx, checkpoints, err := BuildClaim(
		m, c.cfg.CheckpointTapscript, c.cfg.SignerPubKey, c.cfg.EmulatorPubKey,
	)
	if err != nil {
		return err
	}

	arkTxB64, err := arkTx.B64Encode()
	if err != nil {
		return err
	}
	cpB64 := make([]string, len(checkpoints))
	for i, cp := range checkpoints {
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

	_, _, err = c.cfg.Emulator.SubmitTx(ctx, arkTxB64, cpB64)
	return err
}

func validateConfig(cfg Config) error {
	if cfg.Indexer == nil {
		return fmt.Errorf("indexer client must not be nil")
	}
	if cfg.Emulator == nil {
		return fmt.Errorf("emulator client must not be nil")
	}
	if cfg.SecretKey == nil {
		return fmt.Errorf("covclaimd privkey must not be nil")
	}
	if cfg.EmulatorPubKey == nil {
		return fmt.Errorf("emulator pubkey must not be nil")
	}
	if cfg.SignerPubKey == nil {
		return fmt.Errorf("server pubkey must not be nil")
	}
	if len(cfg.CheckpointTapscript) == 0 {
		return fmt.Errorf("checkpoint tapscript must not be empty")
	}
	return nil
}
