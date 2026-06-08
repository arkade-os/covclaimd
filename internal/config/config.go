package config

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/spf13/viper"
)

// Environment variable keys (without the COVCLAIMD_ prefix, which is added by viper).
var (
	SecretKey   = "SECRET_KEY"
	ArkURL      = "ARK_URL"
	EmulatorURL = "EMULATOR_URL"
	GRPCPort    = "GRPC_PORT"
	HTTPPort    = "HTTP_PORT"
	LogLevel    = "LOG_LEVEL"
)

const (
	envPrefix       = "COVCLAIMD"
	defaultGRPCPort = 7070
	defaultHTTPPort = 7071
	defaultLogLevel = 4 // logrus.InfoLevel
)

// Config holds all configuration for the covclaimd server.
type Config struct {
	ArkURL      string
	EmulatorURL string
	SecretKey   *btcec.PrivateKey
	GRPCPort    int
	HTTPPort    int
	LogLevel    int
}

func Load() (*Config, error) {
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	viper.SetDefault(GRPCPort, defaultGRPCPort)
	viper.SetDefault(HTTPPort, defaultHTTPPort)
	viper.SetDefault(LogLevel, defaultLogLevel)

	arkURL := viper.GetString(ArkURL)
	if arkURL == "" {
		return nil, fmt.Errorf("ARK_URL is required")
	}

	emulatorURL := viper.GetString(EmulatorURL)
	if emulatorURL == "" {
		return nil, fmt.Errorf("EMULATOR_URL is required")
	}

	grpcPort := viper.GetInt(GRPCPort)
	httpPort := viper.GetInt(HTTPPort)

	if grpcPort < 1 || grpcPort > 65535 {
		return nil, fmt.Errorf("GRPC_PORT must be between 1 and 65535")
	}
	if httpPort < 1 || httpPort > 65535 {
		return nil, fmt.Errorf("HTTP_PORT must be between 1 and 65535")
	}
	if grpcPort == httpPort {
		return nil, fmt.Errorf("GRPC_PORT and HTTP_PORT must be different")
	}

	secretKeyHex := viper.GetString(SecretKey)
	secretKeyBytes, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key hex")
	}

	seckey, _ := btcec.PrivKeyFromBytes(secretKeyBytes)
	if seckey == nil {
		return nil, fmt.Errorf("failed to parse to secret key")
	}

	return &Config{
		SecretKey:   seckey,
		ArkURL:      arkURL,
		EmulatorURL: emulatorURL,
		GRPCPort:    grpcPort,
		HTTPPort:    httpPort,
		LogLevel:    viper.GetInt(LogLevel),
	}, nil
}
