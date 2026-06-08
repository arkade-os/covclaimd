package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clientgrpc "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	indexergrpc "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/covclaimd/internal/config"
	grpcservice "github.com/arkade-os/covclaimd/internal/interface/grpc"
	"github.com/arkade-os/covclaimd/pkg/preimage"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/arkade-os/solver/pkg/executor"
	"github.com/arkade-os/solver/pkg/executor/arkdsource"
)

// Version is injected at build time via -ldflags "-X main.Version=<tag>".
// Defaults to "dev" for local builds.
var Version = "dev"

func main() {
	if err := run(); err != nil {
		logrus.Error(err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log.SetLevel(logrus.Level(cfg.LogLevel))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.WithField("version", Version).Info("starting covclaimd")

	// The claimer never holds funds and never signs with its own key: it
	// builds claim txs that spend preimage-gated VTXOs via the covenant
	// closure and submits them to the emulator. So it only needs read/submit
	// access to arkd (tx stream + GetInfo) and the indexer (spendable check) —
	// no wallet, seed, or password.
	arkClient, err := clientgrpc.NewClient(cfg.ArkURL)
	if err != nil {
		return fmt.Errorf("failed to connect to arkd: %w", err)
	}
	defer arkClient.Close()

	idxClient, err := indexergrpc.NewClient(cfg.ArkURL)
	if err != nil {
		return fmt.Errorf("failed to connect to indexer: %w", err)
	}
	defer idxClient.Close()

	// Connect to the emulator (covenant signer).
	emulatorConn, err := grpc.NewClient(
		cfg.EmulatorURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to emulator: %w", err)
	}
	// nolint:errcheck
	defer emulatorConn.Close()
	emulator := emulatorclient.NewGRPCClient(emulatorConn)

	emulatorInfo, err := emulator.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get emulator info: %w", err)
	}
	rawEmulatorPub, err := hex.DecodeString(emulatorInfo.SignerPublicKey)
	if err != nil {
		return fmt.Errorf("decode emulator pubkey: %w", err)
	}
	emulatorPub, err := btcec.ParsePubKey(rawEmulatorPub)
	if err != nil {
		return fmt.Errorf("parse emulator pubkey: %w", err)
	}

	info, err := arkClient.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get arkd info: %w", err)
	}

	plugin, err := newPlugin(ctx, cfg, idxClient, emulator, *info, emulatorPub)
	if err != nil {
		return fmt.Errorf("failed to setup preimage plugin: %w", err)
	}

	// Expose the covclaimd/emulator pubkeys over the gRPC + HTTP API.
	handler := grpcservice.NewHandler(grpcservice.PublicKeys{
		PublicKey:         hex.EncodeToString(cfg.SecretKey.PubKey().SerializeCompressed()),
		EmulatorPublicKey: emulatorInfo.SignerPublicKey,
	})
	srv := grpcservice.NewServer(cfg.GRPCPort, cfg.HTTPPort, handler)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer srv.Stop()

	runtimeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	log := logrus.StandardLogger()
	s := executor.New(plugin).WithLogger(log)
	src := arkdsource.New(arkClient, log)
	go func() {
		done <- s.Run(runtimeCtx, src)
	}()

	select {
	case <-ctx.Done():
		cancel()
		<-done
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("runtime exited unexpectedly: %w", err)
		}
	}

	log.Info("covclaimd stopped")
	return nil
}

func newPlugin(
	ctx context.Context,
	cfg *config.Config,
	idx indexer.Indexer,
	emulator emulatorclient.TransportClient,
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

	plugin, err := preimage.NewPlugin(ctx, preimage.Config{
		Indexer:             idx,
		Emulator:            emulator,
		SecretKey:           cfg.SecretKey,
		EmulatorPubKey:      emulatorPub,
		SignerPubKey:        signerPubKey,
		CheckpointTapscript: checkpointBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("build preimage plugin: %w", err)
	}

	return plugin, nil
}
