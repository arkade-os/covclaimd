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
	clientgrpc "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	indexergrpc "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
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
	e2eGRPCPort = 17070
	e2eHTTPPort = 17071
)

var e2eGRPCAddr = fmt.Sprintf("localhost:%d", e2eGRPCPort)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	log.SetLevel(log.DebugLevel)
	ctx := context.Background()

	if err := refillArkd(ctx); err != nil {
		log.Errorf("failed to refill arkd: %s", err)
		return 1
	}

	secretKey, err := btcec.NewPrivateKey()
	if err != nil {
		log.Errorf("failed to generate covclaimd secret key: %s", err)
		return 1
	}

	cfg := &config.Config{
		ArkURL:      arkdURL,
		EmulatorURL: emulatorAddr,
		SecretKey:   secretKey,
		GRPCPort:    e2eGRPCPort,
		HTTPPort:    e2eHTTPPort,
		LogLevel:    int(log.DebugLevel),
	}

	runCtx, cancelCovclaimd := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- runCovclaimd(runCtx, cfg, log.StandardLogger())
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

	return m.Run()
}

func runCovclaimd(
	ctx context.Context, cfg *config.Config, logger log.FieldLogger,
) error {
	emulatorConn, err := grpc.NewClient(
		cfg.EmulatorURL, grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connect to emulator: %w", err)
	}
	defer func() { _ = emulatorConn.Close() }()
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

	arkClient, err := clientgrpc.NewClient(cfg.ArkURL, "covclaimd-e2e")
	if err != nil {
		return fmt.Errorf("connect to arkd: %w", err)
	}
	defer arkClient.Close()

	idxClient, err := indexergrpc.NewClient(cfg.ArkURL)
	if err != nil {
		return fmt.Errorf("connect to indexer: %w", err)
	}
	defer idxClient.Close()

	info, err := arkClient.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("get arkd info: %w", err)
	}

	claimerCfg, err := buildClaimerConfig(cfg, idxClient, emulator, *info, emulatorPub, logger)
	if err != nil {
		return fmt.Errorf("build claimer config: %w", err)
	}

	encrypted, err := preimage.NewPlugin(ctx, claimerCfg)
	if err != nil {
		return fmt.Errorf("build encrypted plugin: %w", err)
	}
	reveal, err := preimage.NewRevealPlugin(claimerCfg)
	if err != nil {
		return fmt.Errorf("build reveal plugin: %w", err)
	}

	handler := grpcservice.NewHandler(grpcservice.PublicKeys{
		PublicKey:         hex.EncodeToString(cfg.SecretKey.PubKey().SerializeCompressed()),
		EmulatorPublicKey: emulatorInfo.SignerPublicKey,
	})
	revealHandler := grpcservice.NewRevealHandler(reveal)
	srv := grpcservice.NewServer(cfg.GRPCPort, cfg.HTTPPort, handler, revealHandler)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	s := executor.New(encrypted, reveal).WithLogger(logger)
	src := arkdsource.New(arkClient, logger)
	return s.Run(ctx, src)
}

func buildClaimerConfig(
	cfg *config.Config,
	idx indexer.Indexer,
	emulator emulatorclient.TransportClient,
	info client.Info,
	emulatorPub *btcec.PublicKey,
	logger log.FieldLogger,
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
		Log:                 logger,
	}, nil
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
	defer func() { _ = conn.Close() }()
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
