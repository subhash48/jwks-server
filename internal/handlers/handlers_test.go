package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/subhash48/jwks-server/internal/jwks"
	"github.com/subhash48/jwks-server/internal/keystore"
)

func TestJWKSOnlyServesUnexpiredKey(t *testing.T) {
	store, err := keystore.NewStore()
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var out jwks.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	if len(out.Keys) != 1 {
		t.Fatalf("expected 1 key (active only), got %d", len(out.Keys))
	}
	if out.Keys[0].KID != store.Active().KID {
		t.Fatalf("expected active kid %s, got %s", store.Active().KID, out.Keys[0].KID)
	}
}

func TestAuthReturnsJWTWithKidAndValidSignature(t *testing.T) {
	store, err := keystore.NewStore()
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/auth", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	tokenStr := string(body)

	parsed, err := jwt.Parse(tokenStr, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		if kid != store.Active().KID {
			t.Fatalf("expected kid %s, got %s", store.Active().KID, kid)
		}
		return &store.Active().Private.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid {
		t.Fatal("expected token to be valid")
	}
}

func TestExpiredAuthUsesExpiredKeyAndExpiredExp(t *testing.T) {
	store, err := keystore.NewStore()
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/auth?expired=1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	tokenStr := string(body)

	parsed, err := jwt.Parse(tokenStr, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		if kid != store.Expired().KID {
			t.Fatalf("expected expired kid %s, got %s", store.Expired().KID, kid)
		}
		return &store.Expired().Private.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithoutClaimsValidation(), // ignore exp validation but still verify signature
	)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid {
		t.Fatal("expected signature to be valid even if exp is past")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("expected exp claim as number")
	}

	// JWT exp is seconds; store expiry has nanoseconds -> compare at second precision.
	exp := time.Unix(int64(expFloat), 0).UTC()
	want := store.Expired().ExpiresAt.UTC().Truncate(time.Second)

	if !exp.Equal(want) {
		t.Fatalf("expected exp == expired key expiry (sec), got %v want %v", exp, want)
	}
	if exp.After(time.Now().UTC()) {
		t.Fatalf("expected exp to be in the past, got %v", exp)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	store, err := keystore.NewStore()
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(store)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
