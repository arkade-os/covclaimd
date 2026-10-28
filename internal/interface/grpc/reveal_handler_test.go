package grpcservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
)

func TestReveal_RefusesAZeroMinAmount(t *testing.T) {
	zero := uint64(0)
	_, err := (&RevealHandler{}).Reveal(context.Background(), &covclaimdv1.RevealRequest{
		Packet: &covclaimdv1.ClaimPacket{
			Ciphertext: []byte{0xaa}, ArkadeScript: []byte{0x51}, MinAmount: &zero,
		},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err), err)
	require.ErrorContains(t, err, "min_amount")
}
