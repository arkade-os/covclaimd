package grpcservice

import (
	"context"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
)

type PublicKeys struct {
	PublicKey, EmulatorPublicKey string
}

type Handler struct {
	covclaimdv1.UnimplementedPreimageServiceServer
	PublicKeys
}

func NewHandler(pubkeys PublicKeys) covclaimdv1.PreimageServiceServer {
	return &Handler{PublicKeys: pubkeys}
}

func (h *Handler) GetCovclaimdPubKey(
	_ context.Context, _ *covclaimdv1.GetCovclaimdPubKeyRequest,
) (*covclaimdv1.GetCovclaimdPubKeyResponse, error) {
	return &covclaimdv1.GetCovclaimdPubKeyResponse{
		CovclaimdPubKey: h.PublicKey,
		EmulatorPubKey:  h.EmulatorPublicKey,
	}, nil
}
