package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/subhash48/jwks-server/internal/jwks"
	"github.com/subhash48/jwks-server/internal/keystore"
)

type Server struct {
	Store *keystore.Store
}

func NewServer(store *keystore.Store) *Server {
	return &Server{Store: store}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Serve JWKS at common paths
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/jwks", s.handleJWKS)

	// Auth endpoint
	mux.HandleFunc("/auth", s.handleAuth)

	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	active := s.Store.Active()

	keys := make([]jwks.JWK, 0, 1)
	// Only serve unexpired keys
	if active.ExpiresAt.After(now) {
		keys = append(keys, jwks.FromRSAPublicKey(active.KID, &active.Private.PublicKey))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks.JWKS{Keys: keys})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// If "expired" query param exists (any value), use expired key.
	_, wantExpired := r.URL.Query()["expired"]

	var kp keystore.KeyPair
	now := time.Now().UTC()

	if wantExpired {
		kp = s.Store.Expired()
	} else {
		kp = s.Store.Active()
	}

	// exp rule:
	// - normal: exp = min(now+5min, key expiry)
	// - expired: exp = key expiry (already in past)
	exp := kp.ExpiresAt
	if !wantExpired {
		candidate := now.Add(5 * time.Minute)
		if candidate.Before(exp) {
			exp = candidate
		}
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"iss": "jwks-server",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kp.KID

	signed, err := token.SignedString(kp.Private)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signed))
}

