package e2e_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	emulatorclient "github.com/arkade-os/emulator/pkg/client"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	clientwallet "github.com/arkade-os/arkd/pkg/client-wallet"
	walletidentity "github.com/arkade-os/arkd/pkg/client-wallet/identity"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-wallet/identity/store/inmemory"
	walletstore "github.com/arkade-os/arkd/pkg/client-wallet/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	password     = "secret"
	arkdURL      = "localhost:7170"
	arkdHTTPURL  = "http://localhost:7171"
	explorerURL  = "http://localhost:3000"
	emulatorAddr = "localhost:7173"
)

func setupArkClient(t *testing.T) clientwallet.Wallet {
	t.Helper()
	ctx := t.Context()

	idStore, err := inmemorystore.NewStore()
	require.NoError(t, err)
	identity, err := walletidentity.NewIdentity(idStore)
	require.NoError(t, err)
	configStore, err := walletstore.NewStore()
	require.NoError(t, err)
	arkClient, err := clientwallet.NewWallet(configStore, clientwallet.WithIdentity(identity))
	require.NoError(t, err)

	require.NoError(t, arkClient.Init(ctx, clientwallet.InitArgs{
		ServerUrl: arkdURL, Password: password, ExplorerURL: explorerURL,
	}))
	require.NoError(t, arkClient.Unlock(ctx, password))
	t.Cleanup(arkClient.Stop)

	return arkClient
}

func faucetOffchain(t *testing.T, client clientwallet.Wallet, amount float64) {
	t.Helper()
	ctx := t.Context()

	note := generateNote(t, uint64(amount*1e8))
	res, err := client.RedeemNotes(ctx, []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, res.CommitmentTxid)

	require.Eventually(t, func() bool {
		spendable, _, err := client.ListVtxos(ctx)
		return err == nil && len(spendable) > 0
	}, 30*time.Second, 200*time.Millisecond, "faucetOffchain: no spendable vtxo after redeeming note")
}

func generateNote(t *testing.T, amount uint64) string {
	t.Helper()
	note, err := generateNoteCtx(t.Context(), amount)
	require.NoError(t, err)
	return note
}

func generateNoteCtx(_ context.Context, amount uint64) (string, error) {
	httpClient := &http.Client{Timeout: 15 * time.Second}
	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", arkdHTTPURL+"/v1/admin/note", reqBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var noteResp struct {
		Notes []string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		return "", err
	}
	if len(noteResp.Notes) == 0 {
		return "", fmt.Errorf("no notes returned from admin API")
	}
	return noteResp.Notes[0], nil
}

func runCommand(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func faucet(ctx context.Context, address string, amount float64) error {
	command := fmt.Sprintf("nigiri faucet %s %.8f", address, amount)
	_, err := runCommand(ctx, command)
	return err
}

func sendOffChainToVHTLC(
	t *testing.T,
	c clientwallet.Wallet,
	claimAddr string,
	amount uint64,
	encodedTapTree []byte,
	pkt extension.Packet,
) {
	t.Helper()

	vhtlcArk, err := arklib.DecodeAddressV0(claimAddr)
	require.NoError(t, err)
	vhtlcPkScript, err := script.P2TRScript(vhtlcArk.VtxoTapKey)
	require.NoError(t, err)

	opts := []offchaintx.Option{offchaintx.WithTxOutsTaprootTree(
		map[string][]byte{hex.EncodeToString(vhtlcPkScript): encodedTapTree},
	)}
	if pkt != nil {
		opts = append(opts, offchaintx.WithExtraPacket(pkt))
	}

	_, err = c.SendOffChain(t.Context(), []clientlib.Receiver{{To: claimAddr, Amount: amount}}, opts...)
	require.NoError(t, err)
}

func newEmulatorClient(t *testing.T) emulatorclient.TransportClient {
	t.Helper()
	conn, err := grpc.NewClient(emulatorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	return emulatorclient.NewGRPCClient(conn)
}

func fetchIntroPubkey(t *testing.T, emulatorClient emulatorclient.TransportClient) *btcec.PublicKey {
	t.Helper()
	info, err := emulatorClient.GetInfo(t.Context())
	require.NoError(t, err)
	raw, err := hex.DecodeString(info.SignerPublicKey)
	require.NoError(t, err)
	pub, err := btcec.ParsePubKey(raw)
	require.NoError(t, err)
	return pub
}

func freshTaprootPkScript(t *testing.T) []byte {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pkScript, err := txscript.PayToTaprootScript(priv.PubKey())
	require.NoError(t, err)
	return pkScript
}

type indexerVtxo struct {
	Txid   string
	VOut   uint32
	Amount uint64
}

func pollForVtxoAt(t *testing.T, ctx context.Context, idx clientlib.Indexer, pkScript []byte, timeout time.Duration) indexerVtxo {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := idx.GetVtxos(ctx,
			clientlib.WithScripts([]string{hex.EncodeToString(pkScript)}),
			clientlib.WithSpendableOnly(),
		)
		if err == nil && len(resp.Vtxos) > 0 {
			v := resp.Vtxos[0]
			return indexerVtxo{Txid: v.Txid, VOut: v.VOut, Amount: v.Amount}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no VTXO appeared at pkScript %s within %v", hex.EncodeToString(pkScript), timeout)
	return indexerVtxo{}
}
