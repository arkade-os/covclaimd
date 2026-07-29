package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	envPrefix       = "COVCLAIMD_"
	defaultGRPCPort = 7070
	defaultHTTPPort = 7071
	defaultLogLevel = 4
	secretKeyLen    = 32
)

type Config struct {
	ArkURL           string
	EmulatorURL      string
	SecretKey        *btcec.PrivateKey
	GRPCPort         int
	HTTPPort         int
	LogLevel         int
	EncryptedEnabled bool
	RevealEnabled    bool
}

func Load() (*Config, error) {
	arkURL := os.Getenv(envPrefix + "ARK_URL")
	if arkURL == "" {
		return nil, fmt.Errorf("ARK_URL is required")
	}

	emulatorURL := os.Getenv(envPrefix + "EMULATOR_URL")
	if emulatorURL == "" {
		return nil, fmt.Errorf("EMULATOR_URL is required")
	}

	grpcPort, err := envInt("GRPC_PORT", defaultGRPCPort)
	if err != nil {
		return nil, err
	}
	httpPort, err := envInt("HTTP_PORT", defaultHTTPPort)
	if err != nil {
		return nil, err
	}
	logLevel, err := envInt("LOG_LEVEL", defaultLogLevel)
	if err != nil {
		return nil, err
	}

	if grpcPort < 1 || grpcPort > 65535 {
		return nil, fmt.Errorf("GRPC_PORT must be between 1 and 65535")
	}
	if httpPort < 1 || httpPort > 65535 {
		return nil, fmt.Errorf("HTTP_PORT must be between 1 and 65535")
	}
	if grpcPort == httpPort {
		return nil, fmt.Errorf("GRPC_PORT and HTTP_PORT must be different")
	}

	secretKeyBytes, err := hex.DecodeString(os.Getenv(envPrefix + "SECRET_KEY"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key hex")
	}
	if len(secretKeyBytes) != secretKeyLen {
		return nil, fmt.Errorf(
			"SECRET_KEY must be %d bytes (%d hex chars), got %d",
			secretKeyLen, secretKeyLen*2, len(secretKeyBytes),
		)
	}

	seckey, _ := btcec.PrivKeyFromBytes(secretKeyBytes)
	if seckey.Key.IsZero() {
		return nil, fmt.Errorf("SECRET_KEY must not be zero")
	}

	encryptedEnabled, err := envBool("ENCRYPTED_ENABLED", true)
	if err != nil {
		return nil, err
	}
	revealEnabled, err := envBool("REVEAL_ENABLED", false)
	if err != nil {
		return nil, err
	}
	if !encryptedEnabled && !revealEnabled {
		return nil, fmt.Errorf("at least one of ENCRYPTED_ENABLED or REVEAL_ENABLED must be true")
	}

	return &Config{
		SecretKey:        seckey,
		ArkURL:           arkURL,
		EmulatorURL:      emulatorURL,
		GRPCPort:         grpcPort,
		HTTPPort:         httpPort,
		LogLevel:         logLevel,
		EncryptedEnabled: encryptedEnabled,
		RevealEnabled:    revealEnabled,
	}, nil
}

func envInt(key string, def int) (int, error) {
	s := os.Getenv(envPrefix + key)
	if s == "" {
		return def, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return v, nil
}

func envBool(key string, def bool) (bool, error) {
	s := os.Getenv(envPrefix + key)
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return v, nil
}
