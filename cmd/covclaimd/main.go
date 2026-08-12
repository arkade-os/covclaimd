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
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clientgrpc "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	indexergrpc "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
	"github.com/arkade-os/covclaimd/internal/config"
	grpcservice "github.com/arkade-os/covclaimd/internal/interface/grpc"
	"github.com/arkade-os/covclaimd/pkg/preimage"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/arkade-os/solver/pkg/executor"
	"github.com/arkade-os/solver/pkg/executor/arkdsource"
)

var Version = "dev"

func main() {
	if err := run(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log.SetLevel(log.Level(cfg.LogLevel))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.WithField("version", Version).Info("starting covclaimd")

	arkClient, err := clientgrpc.NewClient(cfg.ArkURL, "solverd " + Version)
	if err != nil {
		return fmt.Errorf("failed to connect to arkd: %w", err)
	}
	defer arkClient.Close()

	idxClient, err := indexergrpc.NewClient(cfg.ArkURL)
	if err != nil {
		return fmt.Errorf("failed to connect to indexer: %w", err)
	}
	defer idxClient.Close()

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

	claimerCfg, err := buildClaimerConfig(cfg, idxClient, emulator, *info, emulatorPub)
	if err != nil {
		return fmt.Errorf("build claimer config: %w", err)
	}

	plugins := make([]executor.Plugin, 0, 2)
	var revealHandler covclaimdv1.RevealServiceServer

	if cfg.EncryptedEnabled {
		encrypted, err := preimage.NewPlugin(ctx, claimerCfg)
		if err != nil {
			return fmt.Errorf("build encrypted plugin: %w", err)
		}
		plugins = append(plugins, encrypted)
		log.Info("encrypted (Arkade extension) claim plugin enabled")
	}

	if cfg.RevealEnabled {
		reveal, err := preimage.NewRevealPlugin(claimerCfg)
		if err != nil {
			return fmt.Errorf("build reveal plugin: %w", err)
		}
		plugins = append(plugins, reveal)
		revealHandler = grpcservice.NewRevealHandler(reveal)
		log.Info("reveal (direct) claim plugin enabled")
	}

	handler := grpcservice.NewHandler(grpcservice.PublicKeys{
		PublicKey:         hex.EncodeToString(cfg.SecretKey.PubKey().SerializeCompressed()),
		EmulatorPublicKey: emulatorInfo.SignerPublicKey,
	})
	srv := grpcservice.NewServer(cfg.GRPCPort, cfg.HTTPPort, handler, revealHandler)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer srv.Stop()

	logger := log.StandardLogger()
	s := executor.New(plugins...).WithLogger(logger)
	src := arkdsource.New(arkClient, logger)
	if err := s.Run(ctx, src); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("runtime exited unexpectedly: %w", err)
	}

	log.Info("covclaimd stopped")
	return nil
}

func buildClaimerConfig(
	cfg *config.Config,
	idx indexer.Indexer,
	emulator emulatorclient.TransportClient,
	info client.Info,
	emulatorPub *btcec.PublicKey,
) (preimage.Config, error) {
	checkpointBytes, err := hex.DecodeString(info.CheckpointTapscript)
	if err != nil {
		return preimage.Config{}, fmt.Errorf("decode checkpoint tapscript: %w", err)
	}
	signerPubKeyBytes, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return preimage.Config{}, fmt.Errorf("decode signer public key: %w", err)
	}
	signerPubKey, err := btcec.ParsePubKey(signerPubKeyBytes)
	if err != nil {
		return preimage.Config{}, fmt.Errorf("parse signer public key: %w", err)
	}
	return preimage.Config{
		Indexer:             idx,
		Emulator:            emulator,
		SecretKey:           cfg.SecretKey,
		EmulatorPubKey:      emulatorPub,
		SignerPubKey:        signerPubKey,
		CheckpointTapscript: checkpointBytes,
		Log:                 log.StandardLogger(),
	}, nil
}
