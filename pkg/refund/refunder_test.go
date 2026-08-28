package refund

import (
	"context"
	"errors"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
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

func TestNewRefunder_RejectsAnIncompleteConfig(t *testing.T) {
	_, err := NewRefunder(Config{})
	require.Error(t, err)
}

// This is the "someone else already pushed it, or it was never funded" case.
// It must not be confused with success: Refund was asked to push a refund and
// could not, so it returns an error naming why, and it must not have wasted a
// submission attempt on a vtxo it never confirmed exists.
func TestRefund_ReturnsALoudErrorWhenNoSpendableVtxoExists(t *testing.T) {
	v := loadFixture(t, "vhtlc-v2-nine-leaf.json")
	matched := matchedRefundFromFixture(t, v, 50_000)

	submitCalled := false
	idx := &fakeIndexer{getVtxos: func(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error) {
		return &indexer.VtxosResponse{}, nil
	}}
	em := &fakeEmulator{submitTx: func(
		ctx context.Context, tx string, checkpoints []string,
	) (string, []string, error) {
		submitCalled = true
		return "", nil, nil
	}}

	r, err := NewRefunder(testRefunderConfig(t, v, idx, em))
	require.NoError(t, err)

	err = r.Refund(context.Background(), matched)
	require.Error(t, err)
	require.ErrorContains(t, err, "no spendable vtxo")
	require.False(t, submitCalled,
		"must not attempt to submit a refund for a vtxo it never confirmed is spendable")
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
	em := &fakeEmulator{submitTx: func(
		ctx context.Context, tx string, checkpoints []string,
	) (string, []string, error) {
		t.Fatal("must not attempt to submit when the spendable check itself failed")
		return "", nil, nil
	}}

	r, err := NewRefunder(testRefunderConfig(t, v, idx, em))
	require.NoError(t, err)

	err = r.Refund(context.Background(), matched)
	require.ErrorContains(t, err, "indexer unreachable")
}

// The trigger is the CLTV alone, enforced downstream (the same
// CHECKLOCKTIMEVERIFY construction refundWithoutReceiver already relies on in
// production) — Refund adds no grace period of its own, so a premature push
// must surface as exactly the error the emulator gave, not be swallowed or
// silently retried.
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

	err = r.Refund(context.Background(), matched)
	require.ErrorContains(t, err, "premature: locktime not yet satisfied")
}

// The success path: a spendable vtxo, a buildable refund, an emulator that
// accepts it. Refund must actually hand the emulator a real, non-empty
// built transaction (proving BuildRefund's output was threaded through, not
// bypassed) and return no error.
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

	require.NoError(t, r.Refund(context.Background(), matched))
	require.NotEmpty(t, gotTx)
	require.Len(t, gotCheckpoints, 1)
}
