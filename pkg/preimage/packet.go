package preimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcec/v2"
)

const PacketType uint8 = 0x04

const (
	tlvCiphertext      byte = 0x01
	tlvArkadeScript    byte = 0x02
	tlvCovclaimdPubKey byte = 0x03
)

// compressedPubKeyLen is the serialized length of the committed covclaimd key.
const compressedPubKeyLen = 33

type ClaimPacket struct {
	Ciphertext   []byte // encrypted preimage or whatever allowing the claim
	ArkadeScript []byte
	// CovclaimdPubKey is the compressed secp256k1 key the ciphertext is sealed
	// to, in the clear. It names which covclaimd is meant to open this packet,
	// so one can decline another's without attempting the decryption, and so a
	// subscription filter can select its own off an unfiltered stream. It is
	// not a secret and not a capability: the ciphertext is what actually binds
	// the preimage to a key.
	CovclaimdPubKey []byte
}

// AddressedTo reports whether the packet names pub (compressed) as the
// covclaimd meant to open it. A byte compare, deliberately: it settles the
// question before any ECDH or AEAD work, which is the point of committing the
// key at all. A packet that lies here is not a risk, only wasted work — it
// still has to decrypt, and it cannot unless it really was sealed to us.
func (p *ClaimPacket) AddressedTo(pub []byte) bool {
	return len(pub) == compressedPubKeyLen && bytes.Equal(p.CovclaimdPubKey, pub)
}

func (p *ClaimPacket) Decrypt(secretKey *btcec.PrivateKey) ([]byte, error) {
	if _, err := ValidateArkadeScript(p.ArkadeScript); err != nil {
		return nil, fmt.Errorf("invalid arkade_script: %w", err)
	}
	preimg, err := Decrypt(secretKey, p.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt preimage: %w", err)
	}
	if len(preimg) != preimageSize {
		return nil, fmt.Errorf(
			"decrypted preimage has wrong length %d (want %d)", len(preimg), preimageSize,
		)
	}
	return preimg, nil
}

func (p *ClaimPacket) Type() uint8 { return PacketType }

func (p *ClaimPacket) Serialize() ([]byte, error) {
	if len(p.Ciphertext) == 0 {
		return nil, errors.New("ciphertext must not be empty")
	}
	if len(p.ArkadeScript) == 0 {
		return nil, errors.New("arkade_script must not be empty")
	}
	if len(p.CovclaimdPubKey) != compressedPubKeyLen {
		return nil, fmt.Errorf(
			"covclaimd_pub_key must be %d bytes, got %d",
			compressedPubKeyLen, len(p.CovclaimdPubKey),
		)
	}
	buf := &bytes.Buffer{}
	encodeTLV(buf, tlvCiphertext, p.Ciphertext)
	encodeTLV(buf, tlvArkadeScript, p.ArkadeScript)
	encodeTLV(buf, tlvCovclaimdPubKey, p.CovclaimdPubKey)
	return buf.Bytes(), nil
}

func (p *ClaimPacket) ToPacket() (extension.Packet, error) {
	body, err := p.Serialize()
	if err != nil {
		return nil, err
	}
	return extension.UnknownPacket{PacketType: PacketType, Data: body}, nil
}

func DeserializeClaim(data []byte) (*ClaimPacket, error) {
	out := &ClaimPacket{}
	hasCiphertext := false
	hasArkadeScript := false
	hasCovclaimdPubKey := false

	offset := 0
	for offset < len(data) {
		if offset+3 > len(data) {
			return nil, errors.New("truncated TLV: not enough bytes for type+length header")
		}
		tlvType := data[offset]
		tlvLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		if offset+tlvLen > len(data) {
			return nil, fmt.Errorf("truncated TLV: type 0x%02x wants %d bytes, %d left",
				tlvType, tlvLen, len(data)-offset)
		}
		val := make([]byte, tlvLen)
		copy(val, data[offset:offset+tlvLen])
		offset += tlvLen

		switch tlvType {
		case tlvCiphertext:
			out.Ciphertext = val
			hasCiphertext = true
		case tlvArkadeScript:
			out.ArkadeScript = val
			hasArkadeScript = true
		case tlvCovclaimdPubKey:
			// Length only. Parsing the point here would undo the reason this
			// field exists: AddressedTo compares it to a key we already know is
			// on the curve, so bytes that are not are simply not ours.
			if len(val) != compressedPubKeyLen {
				return nil, fmt.Errorf(
					"covclaimd_pub_key TLV (0x03) is %d bytes, want %d",
					len(val), compressedPubKeyLen,
				)
			}
			out.CovclaimdPubKey = val
			hasCovclaimdPubKey = true
		}
	}

	if !hasCiphertext {
		return nil, errors.New("missing ciphertext TLV (0x01)")
	}
	if !hasArkadeScript {
		return nil, errors.New("missing arkade_script TLV (0x02)")
	}
	if !hasCovclaimdPubKey {
		return nil, errors.New("missing covclaimd_pub_key TLV (0x03)")
	}
	return out, nil
}

func FindClaim(ext extension.Extension) (*ClaimPacket, error) {
	p := ext.GetPacketByType(PacketType)
	if p == nil {
		return nil, nil
	}
	unknown, ok := p.(extension.UnknownPacket)
	if !ok {
		return nil, fmt.Errorf(
			"preimage packet (type 0x%02x) has unexpected concrete type %T",
			PacketType, p,
		)
	}
	return DeserializeClaim(unknown.Data)
}

func encodeTLV(buf *bytes.Buffer, tlvType byte, value []byte) {
	buf.WriteByte(tlvType)
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(value)))
	buf.Write(hdr)
	buf.Write(value)
}
