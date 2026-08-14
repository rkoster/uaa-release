// Command softkey-remote-signer is a software implementation of the UAA
// signing service, for acceptance tests only.
//
// It generates an RSA key pair at startup and signs with it in process. That
// is the opposite of what the signing service exists to provide: a real
// implementation delegates to a key store that never releases private key
// material. Never deploy this outside a test environment.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "acceptance_tests/internal/signerpb"
)

type keyRefList []string

func (k *keyRefList) String() string     { return strings.Join(*k, ",") }
func (k *keyRefList) Set(v string) error { *k = append(*k, v); return nil }

type server struct {
	pb.UnimplementedSigningServiceServer
	keys map[string]*rsa.PrivateKey
}

func newServer(keyRefs ...string) (*server, error) {
	keys := make(map[string]*rsa.PrivateKey, len(keyRefs))
	for _, ref := range keyRefs {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generating key %s: %w", ref, err)
		}
		keys[ref] = key
	}
	return &server{keys: keys}, nil
}

func (s *server) GetPublicKey(_ context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	key, ok := s.keys[req.KeyRef]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown key reference %q", req.KeyRef)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshalling public key: %v", err)
	}
	return &pb.GetPublicKeyResponse{
		PublicKeyDer: der,
		Algorithm:    "RS256",
		KeyVersion:   "softkey-v1",
	}, nil
}

func (s *server) Sign(_ context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	key, ok := s.keys[req.KeyRef]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown key reference %q", req.KeyRef)
	}
	if req.Algorithm != "RS256" {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported algorithm %q", req.Algorithm)
	}
	if len(req.Digest) != 32 {
		return nil, status.Errorf(codes.InvalidArgument,
			"RS256 expects a 32 byte digest, got %d", len(req.Digest))
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, req.Digest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing: %v", err)
	}
	return &pb.SignResponse{Signature: signature, KeyVersion: "softkey-v1"}, nil
}

func main() {
	socket := flag.String("socket", "", "unix socket path to bind")
	var refs keyRefList
	flag.Var(&refs, "key-ref", "key reference this plugin serves (repeatable)")
	acknowledged := flag.Bool("i-understand-this-is-not-secure", false,
		"required: acknowledges that this signs with a software key held in memory")
	flag.Parse()

	if !*acknowledged {
		log.Fatal("refusing to start: this plugin signs with a software key held in " +
			"process memory and provides none of the protection of a real key store. " +
			"Pass --i-understand-this-is-not-secure to use it in a test environment.")
	}
	if *socket == "" || len(refs) == 0 {
		log.Fatal("both --socket and at least one --key-ref are required")
	}

	log.Printf("WARNING: softkey-remote-signer is signing with an in-memory software key. " +
		"This is for testing only and must never be used in production.")

	if err := os.Remove(*socket); err != nil && !os.IsNotExist(err) {
		log.Fatalf("removing stale socket %s: %v", *socket, err)
	}
	// Set a restrictive umask before binding, so the socket is created at
	// 0660 atomically rather than briefly existing world-writable between
	// net.Listen and a later os.Chmod.
	oldUmask := syscall.Umask(0o117)
	listener, err := net.Listen("unix", *socket)
	syscall.Umask(oldUmask)
	if err != nil {
		log.Fatalf("binding %s: %v", *socket, err)
	}
	if err := os.Chmod(*socket, 0o660); err != nil {
		log.Fatalf("chmod %s: %v", *socket, err)
	}

	srv, err := newServer(refs...)
	if err != nil {
		log.Fatalf("starting: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterSigningServiceServer(grpcServer, srv)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		grpcServer.GracefulStop()
	}()

	log.Printf("serving key references %v on %s", []string(refs), *socket)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("serving: %v", err)
	}
}
