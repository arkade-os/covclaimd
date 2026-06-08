package e2e_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	arksdk "github.com/arkade-os/go-sdk"
	sdktypes "github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
	"github.com/arkade-os/covclaimd/internal/config"
	grpcservice "github.com/arkade-os/covclaimd/internal/interface/grpc"
	"github.com/arkade-os/covclaimd/pkg/preimage"
	"github.com/arkade-os/solver/pkg/executor"
	"github.com/arkade-os/solver/pkg/executor/arkdsource"
)

const (
	// e2eGRPCPort + e2eHTTPPort are the ports the e2e gRPC server binds to.
	// They're separate from cmd/covclaimd's defaults (7070/7071) so a developer
	// can run both in parallel.
	e2eGRPCPort = 17070
	e2eHTTPPort = 17071
)

// e2eGRPCAddr is the address tests dial to act as a real client of the bot's
// gRPC API.
var e2eGRPCAddr = fmt.Sprintf("localhost:%d", e2eGRPCPort)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

// runTests wraps the test setup so deferred cleanups (temp dirs, DB handles,
// service stops) actually run before the process exits — os.Exit in TestMain
// would skip them otherwise.
func runTests(m *testing.M) int {
	log.SetLevel(log.DebugLevel)
	ctx := context.Background()

	if err := refillArkd(ctx); err != nil {
		log.Errorf("failed to refill arkd: %s", err)
		return 1
	}

	covclaimdDatadir, err := os.MkdirTemp("", "covclaimd-e2e-*")
	if err != nil {
		log.Errorf("failed to create covclaimd datadir: %s", err)
		return 1
	}
	// nolint:errcheck
	defer os.RemoveAll(covclaimdDatadir)

	secretKey, err := btcec.NewPrivateKey()
	if err != nil {
		log.Errorf("failed to generate covclaimd secret key: %s", err)
		return 1
	}

	cfg := &config.Config{
		Datadir:        covclaimdDatadir,
		ArkURL:         arkdURL,
		WalletPassword: password,
		EmulatorURL:    emulatorAddr,
		SecretKey:      secretKey,
		GRPCPort:       e2eGRPCPort,
		HTTPPort:       e2eHTTPPort,
		LogLevel:       int(log.DebugLevel),
	}

	covclaimdWallet, err := setupCovclaimdWallet(ctx, cfg)
	if err != nil {
		log.Errorf("failed to setup covclaimd wallet: %s", err)
		return 1
	}
	defer covclaimdWallet.Stop()

	runCtx, cancelCovclaimd := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- runCovclaimd(runCtx, cfg, log.StandardLogger(), covclaimdWallet)
	}()
	defer func() {
		cancelCovclaimd()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("covclaimd exited during shutdown: %s", err)
		}
	}()

	if err := waitCovclaimdReady(ctx); err != nil {
		log.Errorf("failed waiting for covclaimd readiness: %s", err)
		return 1
	}

	if err := waitWalletSynced(ctx, covclaimdWallet); err != nil {
		log.Errorf("failed to sync covclaimd wallet: %s", err)
		return 1
	}

	// Fund the covclaimd with offchain BTC.
	if err := fundWallet(ctx, covclaimdWallet); err != nil {
		log.Errorf("failed to fund covclaimd: %s", err)
		return 1
	}

	return m.Run()
}

// setupCovclaimdWallet builds, inits, and unlocks the bot's ark wallet on the
// configured datadir. Mirrors cmd/covclaimd's wallet bootstrap.
func setupCovclaimdWallet(ctx context.Context, cfg *config.Config) (arksdk.Wallet, error) {
	wallet, err := arksdk.NewWallet(cfg.Datadir, arksdk.WithoutAutoSettle())
	if err != nil {
		return nil, fmt.Errorf("create wallet: %w", err)
	}
	if err := wallet.Init(ctx, cfg.ArkURL, cfg.WalletSeed, cfg.WalletPassword); err != nil {
		return nil, fmt.Errorf("init wallet: %w", err)
	}
	if err := wallet.Unlock(ctx, cfg.WalletPassword); err != nil {
		return nil, fmt.Errorf("unlock wallet: %w", err)
	}
	return wallet, nil
}

// runCovclaimd boots the gRPC/HTTP server and the covclaimd runtime against the given
// wallet, blocking until ctx is canceled. Mirrors cmd/covclaimd's run().
func runCovclaimd(
	ctx context.Context, cfg *config.Config, logger log.FieldLogger, wallet arksdk.Wallet,
) error {
	emulatorConn, err := grpc.NewClient(
		cfg.EmulatorURL, grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connect to emulator: %w", err)
	}
	// nolint:errcheck
	defer emulatorConn.Close()
	emulator := emulatorclient.NewGRPCClient(emulatorConn)

	emulatorInfo, err := emulator.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("get emulator info: %w", err)
	}
	rawEmulatorPub, err := hex.DecodeString(emulatorInfo.SignerPublicKey)
	if err != nil {
		return fmt.Errorf("decode emulator pubkey: %w", err)
	}
	emulatorPub, err := btcec.ParsePubKey(rawEmulatorPub)
	if err != nil {
		return fmt.Errorf("parse emulator pubkey: %w", err)
	}

	info, err := wallet.Client().GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("get arkd info: %w", err)
	}

	plugin, err := buildPreimagePlugin(ctx, cfg, wallet.Indexer(), emulator, logger, *info, emulatorPub)
	if err != nil {
		return fmt.Errorf("setup preimage plugin: %w", err)
	}

	handler := grpcservice.NewHandler(grpcservice.PublicKeys{
		PublicKey:         hex.EncodeToString(cfg.SecretKey.PubKey().SerializeCompressed()),
		EmulatorPublicKey: emulatorInfo.SignerPublicKey,
	})
	srv := grpcservice.NewServer(cfg.GRPCPort, cfg.HTTPPort, handler)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	s := executor.New(plugin).WithLogger(logger)
	src := arkdsource.New(wallet.Client(), logger)
	return s.Run(ctx, src)
}

func buildPreimagePlugin(
	ctx context.Context,
	cfg *config.Config,
	idx indexer.Indexer,
	emulator emulatorclient.TransportClient,
	logger log.FieldLogger,
	info client.Info,
	emulatorPub *btcec.PublicKey,
) (executor.Plugin, error) {
	checkpointBytes, err := hex.DecodeString(info.CheckpointTapscript)
	if err != nil {
		return nil, fmt.Errorf("decode checkpoint tapscript: %w", err)
	}
	signerPubKeyBytes, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode signer public key: %w", err)
	}
	signerPubKey, err := btcec.ParsePubKey(signerPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse signer public key: %w", err)
	}
	return preimage.NewPlugin(ctx, preimage.Config{
		Indexer:             idx,
		Emulator:            emulator,
		SecretKey:           cfg.SecretKey,
		EmulatorPubKey:      emulatorPub,
		SignerPubKey:        signerPubKey,
		CheckpointTapscript: checkpointBytes,
		Log:                 logger,
	})
}

func waitCovclaimdReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	conn, err := grpc.NewClient(e2eGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	// nolint:errcheck
	defer conn.Close()
	client := covclaimdv1.NewPreimageServiceClient(conn)

	for {
		callCtx, callCancel := context.WithTimeout(ctx, time.Second)
		resp, err := client.GetCovclaimdPubKey(callCtx, &covclaimdv1.GetCovclaimdPubKeyRequest{})
		callCancel()
		if err == nil && resp.GetCovclaimdPubKey() != "" {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitWalletSynced(ctx context.Context, client arksdk.Wallet) error {
	synced := <-client.IsSynced(ctx)
	if synced.Err != nil {
		return fmt.Errorf("wallet sync: %w", synced.Err)
	}
	if !synced.Synced {
		return fmt.Errorf("wallet failed to sync")
	}
	return nil
}

// fundWallet tops up the bot's offchain balance via an admin-issued note, using
// the wallet's vtxo event channel as the wait barrier — same pattern as
// go-sdk's test/e2e faucetOffchain.
func fundWallet(ctx context.Context, client arksdk.Wallet) error {
	bal, err := client.Balance(ctx)
	if err != nil {
		return err
	}
	if bal.OffchainBalance.Total >= 100000 {
		return nil // already funded
	}

	note, err := generateNoteCtx(ctx, 200000) // 200k sats
	if err != nil {
		return fmt.Errorf("failed to generate note: %w", err)
	}

	vtxoCh := client.GetVtxoEventChannel(ctx)

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-waitCtx.Done():
				return
			case ev, ok := <-vtxoCh:
				if !ok {
					return
				}
				if ev.Type == sdktypes.VtxosAdded && len(ev.Vtxos) > 0 {
					return
				}
			}
		}
	}()

	if _, err := client.RedeemNotes(ctx, []string{note}); err != nil {
		return fmt.Errorf("failed to redeem note: %w", err)
	}

	select {
	case <-done:
		return nil
	case <-waitCtx.Done():
		return fmt.Errorf("fundWallet: timed out waiting for VtxosAdded event")
	}
}

func refillArkd(ctx context.Context) error {
	arkdExec := "docker exec covclaimd-arkd arkd"
	command := fmt.Sprintf("%s wallet balance", arkdExec)
	out, err := runCommand(ctx, command)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`available:\s*([0-9]+\.[0-9]+)`)
	matches := re.FindStringSubmatch(out)
	if len(matches) < 2 {
		return fmt.Errorf("could not parse arkd balance from: %s", out)
	}
	balance, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return err
	}
	if delta := 5.0 - balance; delta >= 1 {
		addrCmd := fmt.Sprintf("%s wallet address", arkdExec)
		address, err := runCommand(ctx, addrCmd)
		if err != nil {
			return err
		}
		for range int(delta) {
			if err := faucet(ctx, strings.TrimSpace(address), 1); err != nil {
				return err
			}
		}
	}
	time.Sleep(5 * time.Second)
	return nil
}
