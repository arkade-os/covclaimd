package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultsEncryptedOnly(t *testing.T) {
	t.Setenv("COVCLAIMD_ARK_URL", "localhost:7070")
	t.Setenv("COVCLAIMD_EMULATOR_URL", "localhost:7273")
	t.Setenv("COVCLAIMD_SECRET_KEY", "ed1f6ad1c0aa1bbdcc14a4dc26ff5d31cca6df11617f2bbb24a4e0e6f72f7a5d")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.EncryptedEnabled, "encrypted defaults on")
	assert.False(t, cfg.RevealEnabled, "reveal defaults off")
}

func TestLoad_BothDisabledIsError(t *testing.T) {
	t.Setenv("COVCLAIMD_ARK_URL", "localhost:7070")
	t.Setenv("COVCLAIMD_EMULATOR_URL", "localhost:7273")
	t.Setenv("COVCLAIMD_SECRET_KEY", "ed1f6ad1c0aa1bbdcc14a4dc26ff5d31cca6df11617f2bbb24a4e0e6f72f7a5d")
	t.Setenv("COVCLAIMD_ENCRYPTED_ENABLED", "false")
	t.Setenv("COVCLAIMD_REVEAL_ENABLED", "false")

	_, err := Load()
	require.Error(t, err)
}

func TestLoad_RevealOnly(t *testing.T) {
	t.Setenv("COVCLAIMD_ARK_URL", "localhost:7070")
	t.Setenv("COVCLAIMD_EMULATOR_URL", "localhost:7273")
	t.Setenv("COVCLAIMD_SECRET_KEY", "ed1f6ad1c0aa1bbdcc14a4dc26ff5d31cca6df11617f2bbb24a4e0e6f72f7a5d")
	t.Setenv("COVCLAIMD_ENCRYPTED_ENABLED", "false")
	t.Setenv("COVCLAIMD_REVEAL_ENABLED", "true")

	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.EncryptedEnabled)
	assert.True(t, cfg.RevealEnabled)
}
