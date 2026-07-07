package preimage_test

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
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
			ExpectedSerialized string `json:"expected_serialized"`
		} `json:"valid"`
		InvalidSerialize []struct {
			Name          string `json:"name"`
			Ciphertext    string `json:"ciphertext"`
			ArkadeScript  string `json:"arkade_script"`
			ExpectedError string `json:"expected_error"`
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
				Ciphertext:   fromHex(t, tc.Ciphertext),
				ArkadeScript: fromHex(t, tc.ArkadeScript),
			}
			raw, err := pkt.Serialize()
			require.NoError(t, err)
			assert.Equal(t, tc.ExpectedSerialized, hex.EncodeToString(raw))

			out, err := preimage.DeserializeClaim(raw)
			require.NoError(t, err)
			assert.Equal(t, pkt.Ciphertext, out.Ciphertext)
			assert.Equal(t, pkt.ArkadeScript, out.ArkadeScript)
		})
	}

	for _, tc := range f.ClaimPacket.InvalidSerialize {
		t.Run(tc.Name, func(t *testing.T) {
			pkt := preimage.ClaimPacket{
				Ciphertext:   fromHex(t, tc.Ciphertext),
				ArkadeScript: fromHex(t, tc.ArkadeScript),
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
		Ciphertext:   []byte{0x01, 0x02},
		ArkadeScript: []byte{0x51, 0x20, 0xaa},
	}
	pkt, err := p.ToPacket()
	require.NoError(t, err)
	ext := extension.Extension{pkt}
	found, err := preimage.FindClaim(ext)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, p.Ciphertext, found.Ciphertext)
	assert.Equal(t, p.ArkadeScript, found.ArkadeScript)
}

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
