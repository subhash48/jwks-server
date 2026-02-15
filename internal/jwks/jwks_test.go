package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestFromRSAPublicKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	j := FromRSAPublicKey("kid123", &priv.PublicKey)

	if j.KTY != "RSA" {
		t.Fatalf("expected kty RSA, got %s", j.KTY)
	}
	if j.KID != "kid123" {
		t.Fatalf("expected kid kid123, got %s", j.KID)
	}
	if j.N == "" || j.E == "" {
		t.Fatal("expected non-empty n and e")
	}
	if j.E != "AQAB" {
		t.Fatalf("expected e AQAB, got %s", j.E)
	}
}
