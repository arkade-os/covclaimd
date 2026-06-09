package grpcservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	covclaimdv1 "github.com/arkade-os/covclaimd/api-spec/protobuf/gen/go/covclaimd/v1"
	log "github.com/sirupsen/logrus"
)

// Server manages the gRPC server and HTTP REST gateway.
type Server struct {
	grpcServer      *grpc.Server
	httpServer      *http.Server
	grpcConn        *grpc.ClientConn
	preimageHandler covclaimdv1.PreimageServiceServer
	revealHandler   covclaimdv1.RevealServiceServer
	grpcPort        int
	httpPort        int
}

// NewServer creates a new Server that serves both gRPC and HTTP.
func NewServer(
	grpcPort, httpPort int,
	hdl covclaimdv1.PreimageServiceServer,
	revealHdl covclaimdv1.RevealServiceServer,
) *Server {
	s := &Server{
		grpcPort:        grpcPort,
		httpPort:        httpPort,
		preimageHandler: hdl,
		revealHandler:   revealHdl,
	}
	return s
}

// Start starts both the gRPC server and the HTTP gateway.
func (s *Server) Start() error {
	// Start gRPC server
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.grpcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %w", s.grpcPort, err)
	}

	s.grpcServer = grpc.NewServer()
	if s.preimageHandler != nil {
		covclaimdv1.RegisterPreimageServiceServer(s.grpcServer, s.preimageHandler)
	}
	if s.revealHandler != nil {
		covclaimdv1.RegisterRevealServiceServer(s.grpcServer, s.revealHandler)
	}

	go func() {
		log.Infof("gRPC server listening on :%d", s.grpcPort)
		if err := s.grpcServer.Serve(grpcListener); err != nil {
			log.WithError(err).Error("gRPC server failed")
		}
	}()

	// Start HTTP gateway
	grpcAddr := fmt.Sprintf("localhost:%d", s.grpcPort)
	conn, err := grpc.NewClient(
		grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to dial gRPC server: %w", err)
	}
	s.grpcConn = conn

	mux := http.NewServeMux()
	gwHandler := newHTTPGateway(conn, s.preimageHandler, s.revealHandler)
	mux.Handle("/v1/", gwHandler)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.httpPort),
		Handler: mux,
	}

	go func() {
		log.Infof("HTTP gateway listening on :%d", s.httpPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("HTTP gateway failed")
		}
	}()

	return nil
}

// Stop gracefully shuts down both the gRPC server and the HTTP gateway.
func (s *Server) Stop() {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.WithError(err).Error("failed to shutdown HTTP server")
		}
	}
	if s.grpcConn != nil {
		if err := s.grpcConn.Close(); err != nil {
			log.WithError(err).Error("failed to close gRPC connection")
		}
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	log.Info("servers stopped")
}

// newHTTPGateway creates a simple HTTP handler that routes REST requests
// to the gRPC handlers. This is a lightweight alternative to grpc-gateway
// that avoids the full protobuf dependency for hand-written types.
//
// The service may be nil; routes are registered only when it is present.
func newHTTPGateway(
	_ *grpc.ClientConn,
	preimageSvc covclaimdv1.PreimageServiceServer,
	revealSvc covclaimdv1.RevealServiceServer,
) http.Handler {
	mux := http.NewServeMux()
	if preimageSvc != nil {
		registerPreimageRoutes(mux, preimageSvc)
	}
	if revealSvc != nil {
		registerRevealRoutes(mux, revealSvc)
	}
	return mux
}

func registerPreimageRoutes(mux *http.ServeMux, svc covclaimdv1.PreimageServiceServer) {
	mux.HandleFunc("GET /v1/preimage/covclaimd-pubkey", func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.GetCovclaimdPubKey(r.Context(), &covclaimdv1.GetCovclaimdPubKeyRequest{})
		if err != nil {
			httpGRPCError(w, err)
			return
		}
		jsonResponse(w, resp)
	})
}

func jsonResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func httpError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}

func registerRevealRoutes(mux *http.ServeMux, svc covclaimdv1.RevealServiceServer) {
	mux.HandleFunc("POST /v1/reveal", func(w http.ResponseWriter, r *http.Request) {
		// Cap the request body: a reveal payload is a few hundred bytes; 64 KB
		// is generous and bounds memory on this public endpoint.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		var body struct {
			SwapAddress string `json:"swap_address"`
			Packet      struct {
				Ciphertext   string `json:"ciphertext"`    // base64 (standard, padded)
				ArkadeScript string `json:"arkade_script"` // base64 (standard, padded)
			} `json:"packet"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpError(w, err, http.StatusBadRequest)
			return
		}
		ciphertext, err := base64.StdEncoding.DecodeString(body.Packet.Ciphertext)
		if err != nil {
			httpError(w, fmt.Errorf("ciphertext: %w", err), http.StatusBadRequest)
			return
		}
		arkadeScript, err := base64.StdEncoding.DecodeString(body.Packet.ArkadeScript)
		if err != nil {
			httpError(w, fmt.Errorf("arkade_script: %w", err), http.StatusBadRequest)
			return
		}
		resp, err := svc.Reveal(r.Context(), &covclaimdv1.RevealRequest{
			SwapAddress: body.SwapAddress,
			Packet:      &covclaimdv1.ClaimPacket{Ciphertext: ciphertext, ArkadeScript: arkadeScript},
		})
		if err != nil {
			httpGRPCError(w, err)
			return
		}
		jsonResponse(w, resp)
	})
}

// httpGRPCError maps gRPC status codes to HTTP status codes.
func httpGRPCError(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	httpCode := http.StatusInternalServerError
	switch st.Code() {
	case codes.InvalidArgument:
		httpCode = http.StatusBadRequest
	case codes.NotFound:
		httpCode = http.StatusNotFound
	case codes.AlreadyExists:
		httpCode = http.StatusConflict
	case codes.Unimplemented:
		httpCode = http.StatusNotImplemented
	}
	httpError(w, err, httpCode)
}
