package grpcservice

import (
	"context"
	"encoding/hex"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
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

	cipherText := pkt.GetCiphertext()
	arkadeScript := pkt.GetArkadeScript()

	if len(cipherText) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext must not be empty")
	}
	if len(arkadeScript) == 0 {
		return nil, status.Error(codes.InvalidArgument, "arkade_script must not be empty")
	}

	addr, err := arklib.DecodeAddressV0(req.GetSwapAddress())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid swap_address: %s", err)
	}

	rawTaptree, err := hex.DecodeString(req.GetTaptree())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid taptree: %s", err)
	}
	taptree, err := txutils.DecodeTapTree(rawTaptree)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid taptree: %s", err)
	}
	if len(taptree) == 0 {
		return nil, status.Error(codes.InvalidArgument, "taptree must not be empty")
	}

	if err := h.submitter.Submit(
		ctx, *addr, taptree,
		preimage.ClaimPacket{Ciphertext: cipherText, ArkadeScript: arkadeScript},
	); err != nil {
		return nil, status.Error(submitErrorCode(err), err.Error())
	}
	return &covclaimdv1.RevealResponse{}, nil
}

func submitErrorCode(err error) codes.Code {
	if errors.Is(err, preimage.ErrRegistryFull) {
		return codes.ResourceExhausted
	}
	return codes.InvalidArgument
}
