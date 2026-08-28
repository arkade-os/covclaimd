package refund

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// fakeIndexer implements indexer.Indexer by embedding the (nil) interface:
// any method this test does not override panics if Refund ever calls it,
// which is the point — a test that silently starts exercising a new code
// path should fail loudly, not return an unnoticed zero value.
type fakeIndexer struct {
	indexer.Indexer
	getVtxos func(ctx context.Context, opts ...indexer.GetVtxosOption) (*indexer.VtxosResponse, error)
}

func (f *fakeIndexer) GetVtxos(
	ctx context.Context, opts ...indexer.GetVtxosOption,
) (*indexer.VtxosResponse, error) {
	return f.getVtxos(ctx, opts...)
}

// fakeEmulator implements emulatorclient.TransportClient the same way.
type fakeEmulator struct {
	emulatorclient.TransportClient
	submitTx func(ctx context.Context, tx string, checkpoints []string) (string, []string, error)
}

func (f *fakeEmulator) SubmitTx(
	ctx context.Context, tx string, checkpoints []string,
) (string, []string, error) {
	return f.submitTx(ctx, tx, checkpoints)
}

func testRefunderConfig(
	t *testing.T, v fixture, idx indexer.Indexer, em emulatorclient.TransportClient,
) Config {
	t.Helper()
	return Config{
		Indexer:             idx,
		Emulator:            em,
		ServerPubKey:        v.ServerPubKey(),
		EmulatorPubKey:      v.EmulatorPubKey(),
		CheckpointTapscript: checkpointTapscriptFixture(t),
	}
}

// refuseIndexer and refuseEmulator fail the test if reached — used to prove a
// short-circuit (e.g. the local maturity check) really did stop before the
// I/O it is meant to avoid, rather than merely returning the right answer by
// coincidence after doing the I/O anyway.
func refuseIndexer(t *testing.T) *fakeIndexer {
	t.Helper()
	return &fakeIndexer{getVtxos: func(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error) {
		t.Fatal("must not query the indexer")
		return nil, nil
	}}
}

func refuseEmulator(t *testing.T) *fakeEmulator {
	t.Helper()
	return &fakeEmulator{submitTx: func(
		ctx context.Context, tx string, checkpoints []string,
	) (string, []string, error) {
		t.Fatal("must not attempt to submit")
		return "", nil, nil
	}}
}

func TestNewRefunder_RejectsAnIncompleteConfig(t *testing.T) {
	_, err := NewRefunder(Config{})
	require.Error(t, err)
}

// "Nothing at the script" (already spent — most likely the sender got there
// first via refundWithoutReceiver — or never funded) is the design doc's own
// "benign race" outcome, not a fault: Refund must say so via RefundOutcome,
// not via a Go error, and it must not have wasted a submission attempt on a
// vtxo it never confirmed exists.
func TestRefund_SkipsWithNothingAtScriptWhenVtxoIsGone(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	idx := &fakeIndexer{getVtxos: func(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error) {
		return &indexer.VtxosResponse{}, nil
	}}

	r, err := NewRefunder(testRefunderConfig(t, v, idx, refuseEmulator(t)))
	require.NoError(t, err)

	outcome, err := r.Refund(context.Background(), matched)
	require.NoError(t, err)
	require.Empty(t, outcome.Txid)
	require.Equal(t, NothingAtScript, outcome.Skipped)
}

// A not-yet-matured CLTV must skip with a named reason, exactly like the
// nothing-at-script case above — not an error, and not a silent success. The
// closure here is built directly (not decoded from the fixture's serialized
// taptree, whose own refundLocktime is a ts-sdk placeholder block height) so
// this exercises the seconds-based branch that is what refund_locktime
// actually looks like in production (src/core/send.ts's refundLocktimeFor
// returns an absolute unix timestamp). Both the indexer and the emulator
// refuse to be called: the whole point of checking locally is to never reach
// either when the answer is already known.
func TestRefund_SkipsWithReasonWhenNotYetMatured(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")

	farFuture := time.Now().Add(time.Hour).Unix()
	closure := &script.CLTVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{v.ServerPubKey(), v.RefundCosigner()},
		},
		Locktime: arklib.AbsoluteLocktime(farFuture),
	}
	leafScript, err := closure.Script()
	require.NoError(t, err)

	matched := &MatchedRefund{
		Outpoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
		Amount:   50_000,
		SourceTx: wire.NewMsgTx(3),
		Credentials: RefundCredentials{
			ArkadeScript: v.RefundArkadeScript(),
			Taptree:      []string{hex.EncodeToString(leafScript)},
			PkScript:     mustDecodeHex(t, v.Leaves.NonInteractiveRefundWithoutReceiver),
		},
	}

	r, err := NewRefunder(testRefunderConfig(t, v, refuseIndexer(t), refuseEmulator(t)))
	require.NoError(t, err)

	outcome, err := r.Refund(context.Background(), matched)
	require.NoError(t, err)
	require.Empty(t, outcome.Txid)
	require.NotEmpty(t, outcome.Skipped)
	require.Contains(t, outcome.Skipped, "not yet matured")
	require.Contains(t, outcome.Skipped, "refund_locktime")
}

// An indexer transport failure (as opposed to a clean "zero results" answer)
// must read as its own distinct error, not be folded into "already spent".
func TestRefund_PropagatesAnIndexerError(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	idx := &fakeIndexer{getVtxos: func(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error) {
		return nil, errors.New("indexer unreachable")
	}}

	r, err := NewRefunder(testRefunderConfig(t, v, idx, refuseEmulator(t)))
	require.NoError(t, err)

	outcome, err := r.Refund(context.Background(), matched)
	require.ErrorContains(t, err, "indexer unreachable")
	require.Empty(t, outcome.Txid)
	require.Empty(t, outcome.Skipped)
}

// The trigger is the CLTV alone, enforced downstream (the same
// CHECKLOCKTIMEVERIFY construction refundWithoutReceiver already relies on in
// production) — Refund adds no grace period of its own, so a premature push
// must surface as exactly the error the emulator gave, not be swallowed or
// silently retried. (The fixture's own closure has a block-height locktime,
// which the local maturity check cannot verify and so lets through — this
// is what still reaches the emulator, standing in for any genuine rejection.)
func TestRefund_PropagatesTheEmulatorSubmitErrorVerbatim(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	idx := &fakeIndexer{getVtxos: func(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error) {
		return &indexer.VtxosResponse{Vtxos: []types.Vtxo{{}}}, nil
	}}
	em := &fakeEmulator{submitTx: func(
		ctx context.Context, tx string, checkpoints []string,
	) (string, []string, error) {
		return "", nil, errors.New("premature: locktime not yet satisfied")
	}}

	r, err := NewRefunder(testRefunderConfig(t, v, idx, em))
	require.NoError(t, err)

	outcome, err := r.Refund(context.Background(), matched)
	require.ErrorContains(t, err, "premature: locktime not yet satisfied")
	require.Empty(t, outcome.Txid)
	require.Empty(t, outcome.Skipped)
}

// The success path: a spendable vtxo, a buildable refund, an emulator that
// accepts it. Refund must actually hand the emulator a real, non-empty
// built transaction (proving BuildRefund's output was threaded through, not
// bypassed) and return a RefundOutcome carrying a non-empty Txid and no
// error.
func TestRefund_SubmitsTheBuiltTransactionOnSuccess(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	var gotTx string
	var gotCheckpoints []string
	idx := &fakeIndexer{getVtxos: func(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error) {
		return &indexer.VtxosResponse{Vtxos: []types.Vtxo{{}}}, nil
	}}
	em := &fakeEmulator{submitTx: func(
		ctx context.Context, tx string, checkpoints []string,
	) (string, []string, error) {
		gotTx = tx
		gotCheckpoints = checkpoints
		return "signed-ark-tx", []string{"signed-checkpoint"}, nil
	}}

	r, err := NewRefunder(testRefunderConfig(t, v, idx, em))
	require.NoError(t, err)

	outcome, err := r.Refund(context.Background(), matched)
	require.NoError(t, err)
	require.NotEmpty(t, outcome.Txid)
	require.Empty(t, outcome.Skipped)
	require.NotEmpty(t, gotTx)
	require.Len(t, gotCheckpoints, 1)
}
