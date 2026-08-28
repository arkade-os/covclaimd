package refund

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
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

// RefundOutcome is the result of a Refund attempt: either it pushed (Txid
// set) or it deliberately did nothing (Skipped set, naming why). Exactly one
// of the two is ever set — call Pushed rather than reading the fields
// directly, since Go has no sum type to enforce that invariant for you.
//
// Mirrors intent-solver's own `RefundOutcome = { txid } | { skipped }`
// (src/ops/refunds.ts) rather than inventing a second shape for the same
// concept: a refund that found nothing to push is a normal terminal state for
// a permissionless, racing leaf, not a fault. `refundWithoutReceiver` (the
// sender's own key) and this leaf both open at the same CLTV moment and both
// pay the sender, so losing that race is expected, ordinary operation. A
// genuine failure — a malformed taptree, a missing leaf, an emulator
// rejection, an indexer transport error — is still a Go error, never folded
// into Skipped: Skipped means "correctly nothing to do," not "something went
// wrong and we gave up."
type RefundOutcome struct {
	Txid    string
	Skipped string
}

// Pushed reports whether a refund transaction was actually broadcast, and
// its txid if so. A false return means the refund was skipped for a benign
// reason (already spent, or not yet mature) — see Skipped for which.
//
// This is the one obvious, hard-to-misuse way to read a RefundOutcome: the
// struct's two fields cannot stop a caller from reading Txid on a skip and
// silently getting "", or from misreading "no error" as "pushed" without
// checking further. Pushed forces both questions to be asked together.
func (o RefundOutcome) Pushed() (txid string, ok bool) {
	return o.Txid, o.Txid != ""
}

// NothingAtScript mirrors intent-solver's NOTHING_AT_SCRIPT: the vtxo at the
// covenant's pkScript is already spent or was never funded. Most likely
// explanation for "already spent": the sender got there first via
// refundWithoutReceiver.
const NothingAtScript = "nothing-at-script"

// Refunder pushes the non-interactive refund-without-receiver leaf.
//
// The trigger is the CLTV alone: Refund makes exactly one attempt, as soon as
// it is called, with no grace period, no retry/backoff and no configurable
// delay of its own. A deliberate wait here would only be a fudge factor
// masking a mis-sized refundLocktime; pushing at maturity makes a wrong bound
// fail loudly and early instead of quietly.
//
// Refund DOES check maturity locally before attempting anything (see the
// Locktime read in Refund) — that is not a grace period and does not soften
// "push as soon as spendable": immature still means skip immediately, mature
// still means push immediately, and the check changes nothing about
// correctness, since the tapscript's own CHECKLOCKTIMEVERIFY is the real gate
// and cannot be overridden by a local opinion. It exists for two reasons that
// are not correctness: a local rejection names itself ("refund_locktime
// <n> not yet matured: current time <now>") instead of surfacing whatever
// opaque error the emulator happens to return, and a daemon calling Refund on
// a schedule stops hammering the emulator with a doomed submission for as
// long as the gap lasts. The value it checks against comes from nowhere but
// the matched closure itself — never config, never a separate parameter — so
// this check cannot drift from the rule it is trying to anticipate.
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

// maturity reports whether closure's own Locktime has passed, and if not, a
// message naming why.
//
// Only a seconds-based absolute locktime (arklib.AbsoluteLocktime.IsSeconds)
// can be checked here: that comparison is a bare time.Now(), no I/O, no
// dependency this package doesn't already have. A block-height locktime would
// need a chain-tip height oracle Refunder has no access to (neither
// indexer.Indexer nor emulatorclient.TransportClient exposes one) — and per
// `src/core/send.ts`'s `refundLocktimeFor` (`lightning-swap-service`, the
// service that actually produces these values: "Absolute time the user's
// refund path opens, unix seconds"), every refundLocktime this system
// produces in practice is a unix timestamp, comfortably above
// AbsoluteLocktime's 500_000_000 seconds/blocks threshold. A block-height
// locktime only occurs in a synthetic test fixture (ts-sdk's own
// byte-reproducible vectors use a small placeholder like 1000), never in
// production, so treating that case as "unverifiable locally, defer to the
// real enforcement downstream" gives up nothing real — it is exactly the
// behavior this code had before this check existed.
func maturity(closure *script.CLTVMultisigClosure) (matured bool, reason string) {
	if !closure.Locktime.IsSeconds() {
		return true, ""
	}
	locktime := int64(closure.Locktime)
	now := time.Now().Unix()
	if now >= locktime {
		return true, ""
	}
	return false, fmt.Sprintf(
		"refund_locktime %d not yet matured: current time %d (%d second(s) remaining)",
		locktime, now, locktime-now,
	)
}

// Refund builds and submits the refund spend for m.
//
// Every way this can fail to happen produces either a descriptive error or a
// RefundOutcome naming why nothing was pushed — never a bare success that
// hides which of those happened. covclaimd has already shipped a silent
// no-op once on the claim side (PR #4 — a claim that never happened,
// answered HTTP 200, nothing in the logs); the fix here is not "never return
// without a txid," it is "never return without saying which of pushed,
// skipped, or failed happened, and why."
func (r *Refunder) Refund(ctx context.Context, m *MatchedRefund) (RefundOutcome, error) {
	if m == nil {
		return RefundOutcome{}, fmt.Errorf("refund: matched is nil")
	}
	log := r.log.WithField("outpoint", m.Outpoint.String())

	_, closure, err := locateRefundClosure(m.Credentials, r.cfg.ServerPubKey, r.cfg.EmulatorPubKey)
	if err != nil {
		return RefundOutcome{}, fmt.Errorf("refund: find closure: %w", err)
	}
	if matured, reason := maturity(closure); !matured {
		log.WithField("reason", reason).Debug("refund: not yet matured, skipping")
		return RefundOutcome{Skipped: reason}, nil
	}

	pkScriptHex := hex.EncodeToString(m.Credentials.PkScript)
	resp, err := r.cfg.Indexer.GetVtxos(ctx,
		indexer.WithScripts([]string{pkScriptHex}),
		indexer.WithSpendableOnly(),
	)
	if err != nil {
		return RefundOutcome{}, fmt.Errorf("refund: check vtxo spendable at pkScript %s: %w", pkScriptHex, err)
	}
	if len(resp.Vtxos) == 0 {
		log.Debug("refund: nothing at script — already spent (possibly via refundWithoutReceiver) or never funded")
		return RefundOutcome{Skipped: NothingAtScript}, nil
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
		return RefundOutcome{}, fmt.Errorf("refund: build: %w", err)
	}

	arkTxB64, err := arkTx.B64Encode()
	if err != nil {
		return RefundOutcome{}, fmt.Errorf("refund: encode ark tx: %w", err)
	}
	cpB64 := make([]string, len(checkpoints))
	for i, cp := range checkpoints {
		b64, err := cp.B64Encode()
		if err != nil {
			return RefundOutcome{}, fmt.Errorf("refund: encode checkpoint %d: %w", i, err)
		}
		cpB64[i] = b64
	}

	txid := arkTx.UnsignedTx.TxHash().String()
	log.WithField("txid", txid).
		WithField("tx", arkTxB64).
		WithField("checkpoints", cpB64).
		Debug("refund transaction built, submitting")

	if _, _, err := r.cfg.Emulator.SubmitTx(ctx, arkTxB64, cpB64); err != nil {
		return RefundOutcome{}, fmt.Errorf("refund: submit to emulator: %w", err)
	}
	return RefundOutcome{Txid: txid}, nil
}
