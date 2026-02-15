package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"time"
)

type KeyPair struct {
	KID       string
	Private   *rsa.PrivateKey
	ExpiresAt time.Time
}

type Store struct {
	active  KeyPair
	expired KeyPair
}

// NewStore creates one active key (future expiry) and one expired key (past expiry).
func NewStore() (*Store, error) {
	now := time.Now().UTC()

	active, err := generateKey(now.Add(15 * time.Minute))
	if err != nil {
		return nil, err
	}
	expired, err := generateKey(now.Add(-15 * time.Minute))
	if err != nil {
		return nil, err
	}

	return &Store{active: active, expired: expired}, nil
}

func (s *Store) Active() KeyPair  { return s.active }
func (s *Store) Expired() KeyPair { return s.expired }

func generateKey(expiresAt time.Time) (KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		KID:       randomKID(),
		Private:   priv,
		ExpiresAt: expiresAt,
	}, nil
}

func randomKID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

