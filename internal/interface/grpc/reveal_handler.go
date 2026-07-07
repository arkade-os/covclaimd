package grpcservice

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
	"github.com/arkade-os/covclaimd/pkg/preimage"
)

type RevealHandler struct {
	covclaimdv1.UnimplementedRevealServiceServer
	submitter *preimage.RevealPlugin
}

func NewRevealHandler(submitter *preimage.RevealPlugin) covclaimdv1.RevealServiceServer {
	return &RevealHandler{submitter: submitter}
}

func (h *RevealHandler) Reveal(
	ctx context.Context, req *covclaimdv1.RevealRequest,
) (*covclaimdv1.RevealResponse, error) {
	pkt := req.GetPacket()
	if pkt == nil {
		return nil, status.Error(codes.InvalidArgument, "packet is required")
	}
	if err := h.submitter.Submit(
		ctx, req.GetSwapAddress(), pkt.GetCiphertext(), pkt.GetArkadeScript(),
	); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &covclaimdv1.RevealResponse{}, nil
}
