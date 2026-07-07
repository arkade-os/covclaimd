package preimage

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arkade "github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/serialization_fixtures.json
var serializationFixturesJSON []byte

type arkadeScriptFixtures struct {
	ArkadeScript struct {
		Valid []struct {
			Name             string `json:"name"`
			Script           string `json:"script"`
			ExpectedReceiver string `json:"expected_receiver"`
		} `json:"valid"`
		Invalid []struct {
			Name          string `json:"name"`
			Script        string `json:"script"`
			ExpectedError string `json:"expected_error"`
		} `json:"invalid"`
	} `json:"arkade_script"`
}

func TestEnforcePayTo_Determinism(t *testing.T) {
	receiver := fixedReceiver(t)
	a, err := EnforcePayTo(receiver)
	require.NoError(t, err)
	b, err := EnforcePayTo(receiver)
	require.NoError(t, err)
	assert.Equal(t, a, b)
}

func TestEnforcePayTo_RejectsNonP2TR(t *testing.T) {
	t.Run("wrong length", func(t *testing.T) {
		_, err := EnforcePayTo([]byte{0x51, 0x20})
		assert.Error(t, err)
	})
	t.Run("wrong prefix", func(t *testing.T) {
		bad := make([]byte, 34)
		bad[0] = txscript.OP_0
		bad[1] = 0x20
		_, err := EnforcePayTo(bad)
		assert.Error(t, err)
	})
}

func TestPreimageCondition_Shape(t *testing.T) {
	preimage := bytes.Repeat([]byte{0x42}, 32)
	hash := btcutil.Hash160(preimage)

	cond, err := preimageCondition(hash)
	require.NoError(t, err)

	require.Len(t, cond, 23)
	assert.Equal(t, byte(txscript.OP_HASH160), cond[0])
	assert.Equal(t, byte(txscript.OP_DATA_20), cond[1])
	assert.Equal(t, hash, cond[2:22])
	assert.Equal(t, byte(txscript.OP_EQUAL), cond[22])
}

func TestPreimageCondition_RejectsBadLength(t *testing.T) {
	_, err := preimageCondition([]byte{0x01})
	assert.Error(t, err)
	_, err = preimageCondition(make([]byte, 32))
	assert.Error(t, err)
}

func TestCovenantClaimClosure_Determinism(t *testing.T) {
	receiver := fixedReceiver(t)
	server := fixedPub(t, strings.Repeat("02", 32))
	emulator := fixedPub(t, strings.Repeat("03", 32))
	preimageHash := btcutil.Hash160(bytes.Repeat([]byte{0x42}, 32))

	a, err := CovenantClaimClosure(preimageHash, receiver, server, emulator)
	require.NoError(t, err)
	b, err := CovenantClaimClosure(preimageHash, receiver, server, emulator)
	require.NoError(t, err)

	scriptA, err := a.Script()
	require.NoError(t, err)
	scriptB, err := b.Script()
	require.NoError(t, err)
	assert.Equal(t, scriptA, scriptB)
}

func TestCovenantClaimClosure_NilPubkeyRejected(t *testing.T) {
	receiver := fixedReceiver(t)
	preimageHash := btcutil.Hash160(bytes.Repeat([]byte{0x42}, 32))

	_, err := CovenantClaimClosure(preimageHash, receiver, nil, fixedPub(t, strings.Repeat("03", 32)))
	assert.Error(t, err)
	_, err = CovenantClaimClosure(preimageHash, receiver, fixedPub(t, strings.Repeat("02", 32)), nil)
	assert.Error(t, err)
}

func TestCovenantClaimClosure_Shape(t *testing.T) {
	receiver := fixedReceiver(t)
	server := fixedPub(t, strings.Repeat("02", 32))
	emulator := fixedPub(t, strings.Repeat("03", 32))
	preimageHash := btcutil.Hash160(bytes.Repeat([]byte{0x42}, 32))

	c, err := CovenantClaimClosure(preimageHash, receiver, server, emulator)
	require.NoError(t, err)

	cmc, ok := c.(*script.ConditionMultisigClosure)
	require.True(t, ok, "expected ConditionMultisigClosure, got %T", c)
	require.Len(t, cmc.PubKeys, 2)

	enforcement, err := EnforcePayTo(receiver)
	require.NoError(t, err)
	expectedTweaked := arkade.ComputeArkadeScriptPublicKey(
		emulator, arkade.ArkadeScriptHash(enforcement),
	)
	assert.True(t, cmc.PubKeys[0].IsEqual(server))
	assert.True(t, cmc.PubKeys[1].IsEqual(expectedTweaked))

	expectedCondition, err := preimageCondition(preimageHash)
	require.NoError(t, err)
	assert.Equal(t, expectedCondition, cmc.Condition)
}

func TestValidateArkadeScript(t *testing.T) {
	var f arkadeScriptFixtures
	require.NoError(t, json.Unmarshal(serializationFixturesJSON, &f))

	for _, tc := range f.ArkadeScript.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.Script)
			require.NoError(t, err)
			parsed, err := ValidateArkadeScript(raw)
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedReceiver, hex.EncodeToString(parsed))
		})
	}

	for _, tc := range f.ArkadeScript.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.Script)
			require.NoError(t, err)
			_, err = ValidateArkadeScript(raw)
			require.ErrorContains(t, err, tc.ExpectedError)
		})
	}
}

func TestEnforcePayTo_MatchesFixture(t *testing.T) {
	var f arkadeScriptFixtures
	require.NoError(t, json.Unmarshal(serializationFixturesJSON, &f))
	require.NotEmpty(t, f.ArkadeScript.Valid)

	got, err := EnforcePayTo(fixedReceiver(t))
	require.NoError(t, err)
	assert.Equal(t, f.ArkadeScript.Valid[0].Script, hex.EncodeToString(got))
}

func fixedPub(t *testing.T, hexSecret string) *btcec.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(hexSecret)
	require.NoError(t, err)
	priv, _ := btcec.PrivKeyFromBytes(raw)
	return priv.PubKey()
}

func fixedReceiver(t *testing.T) []byte {
	t.Helper()
	pub := fixedPub(t, strings.Repeat("01", 32))
	pkScript, err := txscript.PayToTaprootScript(pub)
	require.NoError(t, err)
	require.Len(t, pkScript, 34)
	return pkScript
}
