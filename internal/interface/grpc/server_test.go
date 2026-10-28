package grpcservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
)

type capturedReveal struct {
	covclaimdv1.UnimplementedRevealServiceServer
	req *covclaimdv1.RevealRequest
}

func (c *capturedReveal) Reveal(
	_ context.Context, req *covclaimdv1.RevealRequest,
) (*covclaimdv1.RevealResponse, error) {
	c.req = req
	return &covclaimdv1.RevealResponse{}, nil
}

func TestRevealRoute_ForwardsMinAmount(t *testing.T) {
	minAmount := uint64(50_000)
	for name, tc := range map[string]struct {
		packet string
		want   *uint64
	}{
		"bound":  {`{"ciphertext":"qg==","arkade_script":"UQ==","min_amount":50000}`, &minAmount},
		"legacy": {`{"ciphertext":"qg==","arkade_script":"UQ=="}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &capturedReveal{}
			rec := httptest.NewRecorder()
			body := `{"swap_address":"a","packet":` + tc.packet + `,"taptree":"00"}`
			newHTTPGateway(nil, svc).ServeHTTP(
				rec, httptest.NewRequest(http.MethodPost, "/v1/reveal", strings.NewReader(body)),
			)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, tc.want, svc.req.GetPacket().MinAmount)
		})
	}
}
