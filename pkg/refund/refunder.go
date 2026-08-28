package refund

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/sirupsen/logrus"
)

// Config is the refund-side twin of preimage.Config. It carries no secret
// key: the non-interactive refund-without-receiver leaf has no packet to
// decrypt and no covclaimd-specific identity to prove against — per the
// design doc, "the leaf is permissionless once mature; whoever holds the
// lockup pushes it."
type Config struct {
	Indexer             indexer.Indexer
	Emulator            emulatorclient.TransportClient
	ServerPubKey        *btcec.PublicKey
	EmulatorPubKey      *btcec.PublicKey
	CheckpointTapscript []byte
	Log                 logrus.FieldLogger
}

func validateConfig(cfg Config) error {
	if cfg.Indexer == nil {
		return fmt.Errorf("indexer client must not be nil")
	}
	if cfg.Emulator == nil {
		return fmt.Errorf("emulator client must not be nil")
	}
	if cfg.EmulatorPubKey == nil {
		return fmt.Errorf("emulator pubkey must not be nil")
	}
	if cfg.ServerPubKey == nil {
		return fmt.Errorf("server pubkey must not be nil")
	}
	if len(cfg.CheckpointTapscript) == 0 {
		return fmt.Errorf("checkpoint tapscript must not be empty")
	}
	return nil
}

// Refunder pushes the non-interactive refund-without-receiver leaf.
//
// The trigger is the CLTV alone: Refund makes exactly one attempt, as soon as
// it is called, with no grace period, no retry/backoff and no configurable
// delay of its own. A deliberate wait here would only be a fudge factor
// masking a mis-sized refundLocktime; pushing at maturity makes a wrong bound
// fail loudly and early instead of quietly. Deciding WHEN the CLTV has
// matured is left entirely to whatever already enforces
// CHECKLOCKTIMEVERIFY for the existing refundWithoutReceiver leaf in
// production (the same construction, per the design doc) — Refunder does not
// re-implement that check, so it cannot silently disagree with it. Callers
// that push too early get the emulator's real rejection back, verbatim.
type Refunder struct {
	cfg Config
	log logrus.FieldLogger
}

// NewRefunder validates cfg and returns a Refunder, or a descriptive error —
// never a Refunder that would fail silently later because of a config gap
// caught too late to matter.
func NewRefunder(cfg Config) (*Refunder, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	return &Refunder{cfg: cfg, log: cfg.Log}, nil
}

// Refund builds and submits the refund spend for m.
//
// Every way this can fail to happen produces a non-nil, descriptive error.
// covclaimd has already shipped a silent no-op once on the claim side (PR
// #4 — a claim that never happened, answered HTTP 200, nothing in the logs)
// and this is the last thing standing between a matured lockup and its
// refund actually reaching the network, so nothing here is allowed to return
// a bare nil that later reads as "nothing to do" when something in fact went
// wrong.
func (r *Refunder) Refund(ctx context.Context, m *MatchedRefund) error {
	if m == nil {
		return fmt.Errorf("refund: matched is nil")
	}
	log := r.log.WithField("outpoint", m.Outpoint.String())

	pkScriptHex := hex.EncodeToString(m.Credentials.PkScript)
	resp, err := r.cfg.Indexer.GetVtxos(ctx,
		indexer.WithScripts([]string{pkScriptHex}),
		indexer.WithSpendableOnly(),
	)
	if err != nil {
		return fmt.Errorf("refund: check vtxo spendable at pkScript %s: %w", pkScriptHex, err)
	}
	if len(resp.Vtxos) == 0 {
		return fmt.Errorf(
			"refund: no spendable vtxo at pkScript %s: already spent, not yet confirmed, or wrong pkScript",
			pkScriptHex,
		)
	}

	log.WithField("amount", m.Amount).
		WithField("arkade_script_hex", hex.EncodeToString(m.Credentials.ArkadeScript)).
		WithField("pk_script_hex", hex.EncodeToString(m.Credentials.PkScript)).
		WithField("taptree_leaves", len(m.Credentials.Taptree)).
		Debug("refund: vtxo confirmed spendable, building ark tx")

	arkTx, checkpoints, err := BuildRefund(
		m, r.cfg.CheckpointTapscript, r.cfg.ServerPubKey, r.cfg.EmulatorPubKey,
	)
	if err != nil {
		return fmt.Errorf("refund: build: %w", err)
	}

	arkTxB64, err := arkTx.B64Encode()
	if err != nil {
		return fmt.Errorf("refund: encode ark tx: %w", err)
	}
	cpB64 := make([]string, len(checkpoints))
	for i, cp := range checkpoints {
		b64, err := cp.B64Encode()
		if err != nil {
			return fmt.Errorf("refund: encode checkpoint %d: %w", i, err)
		}
		cpB64[i] = b64
	}

	log.WithField("txid", arkTx.UnsignedTx.TxHash().String()).
		WithField("tx", arkTxB64).
		WithField("checkpoints", cpB64).
		Debug("refund transaction built, submitting")

	if _, _, err := r.cfg.Emulator.SubmitTx(ctx, arkTxB64, cpB64); err != nil {
		return fmt.Errorf("refund: submit to emulator: %w", err)
	}
	return nil
}
