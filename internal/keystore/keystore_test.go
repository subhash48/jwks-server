package keystore

import (
	"testing"
	"time"
)

func TestNewStoreCreatesActiveAndExpiredKeys(t *testing.T) {
	s, err := NewStore()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()

	if s.Active().KID == "" || s.Expired().KID == "" {
		t.Fatal("expected non-empty kids")
	}
	if s.Active().Private == nil || s.Expired().Private == nil {
		t.Fatal("expected private keys to be non-nil")
	}

	if !s.Active().ExpiresAt.After(now) {
		t.Fatalf("expected active key to expire in future: %v", s.Active().ExpiresAt)
	}
	if !s.Expired().ExpiresAt.Before(now) {
		t.Fatalf("expected expired key to expire in past: %v", s.Expired().ExpiresAt)
	}
}
