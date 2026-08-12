package preimage_test

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkade-os/covclaimd/pkg/preimage"
)

//go:embed testdata/serialization_fixtures.json
var fixturesJSON []byte

type claimPacketFixtures struct {
	ClaimPacket struct {
		Valid []struct {
			Name               string `json:"name"`
			Ciphertext         string `json:"ciphertext"`
			ArkadeScript       string `json:"arkade_script"`
			CovclaimdPubKey    string `json:"covclaimd_pub_key"`
			ExpectedSerialized string `json:"expected_serialized"`
		} `json:"valid"`
		InvalidSerialize []struct {
			Name            string `json:"name"`
			Ciphertext      string `json:"ciphertext"`
			ArkadeScript    string `json:"arkade_script"`
			CovclaimdPubKey string `json:"covclaimd_pub_key"`
			ExpectedError   string `json:"expected_error"`
		} `json:"invalid_serialize"`
		InvalidDeserialize []struct {
			Name          string `json:"name"`
			Data          string `json:"data"`
			ExpectedError string `json:"expected_error"`
		} `json:"invalid_deserialize"`
	} `json:"claim_packet"`
}

func TestClaimPacket_Serialize(t *testing.T) {
	f := loadClaimPacketFixtures(t)

	for _, tc := range f.ClaimPacket.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			pkt := preimage.ClaimPacket{
				Ciphertext:      fromHex(t, tc.Ciphertext),
				ArkadeScript:    fromHex(t, tc.ArkadeScript),
				CovclaimdPubKey: fromHex(t, tc.CovclaimdPubKey),
			}
			raw, err := pkt.Serialize()
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedSerialized, hex.EncodeToString(raw))

			out, err := preimage.DeserializeClaim(raw)
			require.NoError(t, err)
			assert.Equal(t, pkt.Ciphertext, out.Ciphertext)
			assert.Equal(t, pkt.ArkadeScript, out.ArkadeScript)
			assert.Equal(t, pkt.CovclaimdPubKey, out.CovclaimdPubKey)
		})
	}

	for _, tc := range f.ClaimPacket.InvalidSerialize {
		t.Run(tc.Name, func(t *testing.T) {
			pkt := preimage.ClaimPacket{
				Ciphertext:      fromHex(t, tc.Ciphertext),
				ArkadeScript:    fromHex(t, tc.ArkadeScript),
				CovclaimdPubKey: fromHex(t, tc.CovclaimdPubKey),
			}
			_, err := pkt.Serialize()
			require.ErrorContains(t, err, tc.ExpectedError)
		})
	}
}

func TestDeserializeClaim(t *testing.T) {
	f := loadClaimPacketFixtures(t)

	for _, tc := range f.ClaimPacket.InvalidDeserialize {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := preimage.DeserializeClaim(fromHex(t, tc.Data))
			require.ErrorContains(t, err, tc.ExpectedError)
		})
	}
}

func TestClaimPacket_Type(t *testing.T) {
	p := preimage.ClaimPacket{}
	assert.Equal(t, uint8(0x04), p.Type())
}

func TestFindClaim_Found(t *testing.T) {
	p := preimage.ClaimPacket{
		Ciphertext:      []byte{0x01, 0x02},
		ArkadeScript:    []byte{0x51, 0x20, 0xaa},
		CovclaimdPubKey: fromHex(t, generatorPubKeyHex),
	}
	pkt, err := p.ToPacket()
	require.NoError(t, err)
	ext := extension.Extension{pkt}
	found, err := preimage.FindClaim(ext)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, p.Ciphertext, found.Ciphertext)
	assert.Equal(t, p.ArkadeScript, found.ArkadeScript)
	assert.Equal(t, p.CovclaimdPubKey, found.CovclaimdPubKey)
}

// The committed key is what lets a covclaimd decline another's packet without
// attempting the decryption, so the comparison has to be exact in both
// directions: our key accepted, anyone else's refused.
func TestClaimPacket_AddressedTo(t *testing.T) {
	ours := fromHex(t, generatorPubKeyHex)
	p := preimage.ClaimPacket{CovclaimdPubKey: ours}

	assert.True(t, p.AddressedTo(ours))

	t.Run("another covclaimd's key", func(t *testing.T) {
		other, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		assert.False(t, p.AddressedTo(other.PubKey().SerializeCompressed()))
	})

	t.Run("same key, one byte flipped", func(t *testing.T) {
		near := append([]byte(nil), ours...)
		near[len(near)-1] ^= 0x01
		assert.False(t, p.AddressedTo(near))
	})

	t.Run("truncated argument never matches", func(t *testing.T) {
		assert.False(t, p.AddressedTo(ours[:32]))
		assert.False(t, p.AddressedTo(nil))
	})

	t.Run("packet with no committed key matches nothing", func(t *testing.T) {
		empty := preimage.ClaimPacket{}
		assert.False(t, empty.AddressedTo(ours))
	})
}

// This is the predicate the plugin actually declines on, and the distinction it
// draws is the whole of the staged rollout: "names someone else" is a decline,
// "names nobody" is not.
func TestClaimPacket_SealedToAnother(t *testing.T) {
	ours := fromHex(t, generatorPubKeyHex)
	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	theirs := other.PubKey().SerializeCompressed()

	assert.False(t, (&preimage.ClaimPacket{CovclaimdPubKey: ours}).SealedToAnother(ours),
		"our own packet is not another's")
	assert.True(t, (&preimage.ClaimPacket{CovclaimdPubKey: theirs}).SealedToAnother(ours),
		"a packet naming another covclaimd is declined")
	assert.False(t, (&preimage.ClaimPacket{}).SealedToAnother(ours),
		"a packet naming nobody predates the field and must still be tried")
}

// 0x03 is required to write and optional to read. A packet in the two-TLV shape
// that predates the field has to keep parsing and keep claiming — there is one
// stamping that shape today, and rejecting it would strand every swap it funds.
func TestDeserializeClaim_AcceptsPacketWithoutPubKey(t *testing.T) {
	out, err := preimage.DeserializeClaim(fromHex(t, "010001aa02000151"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0xaa}, out.Ciphertext)
	assert.Equal(t, []byte{0x51}, out.ArkadeScript)
	assert.Empty(t, out.CovclaimdPubKey)
	// It names nobody, so it is addressed to nobody — the caller decides what
	// that means, and the plugin treats it as "not for someone else".
	assert.False(t, out.AddressedTo(fromHex(t, generatorPubKeyHex)))
}

// Writing is still strict: nothing this package produces may omit the key, or
// the packets it stamps could never be selected by a subscription filter.
func TestClaimPacket_SerializeStillRequiresPubKey(t *testing.T) {
	_, err := (&preimage.ClaimPacket{
		Ciphertext:   []byte{0xaa},
		ArkadeScript: []byte{0x51},
	}).Serialize()
	require.ErrorContains(t, err, "covclaimd_pub_key must be 33 bytes, got 0")
}

// The decoder does not care what order the TLVs arrive in, and the subscription
// filter is a contains-match for that reason. If this ever became order-
// sensitive, a sender that serialized the other way round would be dropped
// silently, so pin it.
func TestDeserializeClaim_TLVOrderIndependent(t *testing.T) {
	pubKey := fromHex(t, generatorPubKeyHex)
	canonical := fromHex(t, "010001aa020001510300210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	reversed := fromHex(t, "0300210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802000151010001aa")

	for name, data := range map[string][]byte{"canonical": canonical, "reversed": reversed} {
		t.Run(name, func(t *testing.T) {
			out, err := preimage.DeserializeClaim(data)
			require.NoError(t, err)
			assert.Equal(t, []byte{0xaa}, out.Ciphertext)
			assert.Equal(t, []byte{0x51}, out.ArkadeScript)
			assert.Equal(t, pubKey, out.CovclaimdPubKey)
			assert.True(t, out.AddressedTo(pubKey))
		})
	}
}

// secp256k1 generator, compressed. Any 33 bytes would satisfy the codec, which
// checks length only; a real point is used so the same fixtures can be handed
// to AddressedTo without implying the codec validates the curve.
const generatorPubKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func TestFindClaim_NotFound(t *testing.T) {
	other := extension.UnknownPacket{PacketType: 0xff, Data: []byte{0x00}}
	ext := extension.Extension{other}
	found, err := preimage.FindClaim(ext)
	require.NoError(t, err)
	require.Nil(t, found)
}

func loadClaimPacketFixtures(t *testing.T) claimPacketFixtures {
	t.Helper()
	var f claimPacketFixtures
	require.NoError(t, json.Unmarshal(fixturesJSON, &f))
	return f
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
