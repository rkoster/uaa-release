package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	pb "acceptance_tests/internal/signerpb"
)

func TestSignProducesAVerifiableSignature(t *testing.T) {
	srv, err := newServer("test-key")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}

	pubResp, err := srv.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyRef: "test-key"})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	parsed, err := x509.ParsePKIXPublicKey(pubResp.PublicKeyDer)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	digest := sha256.Sum256([]byte("header.payload"))
	signResp, err := srv.Sign(context.Background(), &pb.SignRequest{
		KeyRef: "test-key", Digest: digest[:], Algorithm: "RS256",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(parsed.(*rsa.PublicKey), crypto.SHA256, digest[:], signResp.Signature); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestUnknownKeyRefIsRejected(t *testing.T) {
	srv, err := newServer("test-key")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if _, err := srv.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyRef: "other"}); err == nil {
		t.Fatal("expected an error for an unknown key reference")
	}
}

func TestSignRejectsAnUnknownKeyRef(t *testing.T) {
	srv, err := newServer("test-key")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	digest := sha256.Sum256([]byte("header.payload"))
	if _, err := srv.Sign(context.Background(), &pb.SignRequest{
		KeyRef: "other", Digest: digest[:], Algorithm: "RS256",
	}); err == nil {
		t.Fatal("expected an error for an unknown key reference")
	}
}

func TestSignRejectsAnUnsupportedAlgorithm(t *testing.T) {
	srv, err := newServer("test-key")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	digest := sha256.Sum256([]byte("header.payload"))
	if _, err := srv.Sign(context.Background(), &pb.SignRequest{
		KeyRef: "test-key", Digest: digest[:], Algorithm: "ES256",
	}); err == nil {
		t.Fatal("expected an error for an unsupported algorithm")
	}
}

func TestSignRejectsAWrongLengthDigest(t *testing.T) {
	srv, err := newServer("test-key")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if _, err := srv.Sign(context.Background(), &pb.SignRequest{
		KeyRef: "test-key", Digest: []byte("too-short"), Algorithm: "RS256",
	}); err == nil {
		t.Fatal("expected an error for a wrong-length digest")
	}
}
