package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/subhash48/jwks-server/internal/jwks"
	"github.com/subhash48/jwks-server/internal/keystore"
)

func newTestStore(t *testing.T) *keystore.DBStore {
	t.Helper()

	tmp := t.TempDir()
	dbPath := tmp + "/" + keystore.DBFileName

	store, err := keystore.NewDBStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func postAuth(t *testing.T, url string) *http.Response {
	t.Helper()

	body := bytes.NewBufferString(`{"username":"userABC","password":"password123"}`)
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("userABC", "password123")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestJWKSOnlyServesUnexpiredKeys(t *testing.T) {
	store := newTestStore(t)

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

	validKeys, err := store.GetValidKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(validKeys) == 0 {
		t.Fatal("expected at least one valid key in DB")
	}

	// JWKS should include only valid keys
	if len(out.Keys) != len(validKeys) {
		t.Fatalf("expected %d jwks keys, got %d", len(validKeys), len(out.Keys))
	}

	// expired key kid should NOT be in JWKS
	expiredKey, err := store.GetSigningKey(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	expiredKid := strconv.FormatInt(expiredKey.KID, 10)

	for _, k := range out.Keys {
		if k.KID == expiredKid {
			t.Fatalf("expired key kid %s should not be in JWKS", k.KID)
		}
	}
}

func TestAuthReturnsValidJWTWithKid(t *testing.T) {
	store := newTestStore(t)

	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp := postAuth(t, ts.URL+"/auth")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d, body=%s", resp.StatusCode, string(b))
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenStr := string(tokenBytes)

	validKeys, err := store.GetValidKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(validKeys) == 0 {
		t.Fatal("expected at least one valid key in DB")
	}

	pub := &validKeys[0].Private.PublicKey
	wantKid := strconv.FormatInt(validKeys[0].KID, 10)

	parsed, err := jwt.Parse(tokenStr, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		if kid != wantKid {
			t.Fatalf("expected kid %s, got %s", wantKid, kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid {
		t.Fatal("expected token to be valid")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}
	expNum, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("expected exp to be a number")
	}
	if time.Unix(int64(expNum), 0).Before(time.Now().UTC()) {
		t.Fatal("expected exp to be in the future for non-expired auth")
	}
}

func TestExpiredAuthUsesExpiredKeyAndExpiredExp(t *testing.T) {
	store := newTestStore(t)

	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp := postAuth(t, ts.URL+"/auth?expired=1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d, body=%s", resp.StatusCode, string(b))
	}

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenStr := string(tokenBytes)

	expiredKey, err := store.GetSigningKey(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	wantKid := strconv.FormatInt(expiredKey.KID, 10)

	parsed, err := jwt.Parse(tokenStr, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		if kid != wantKid {
			t.Fatalf("expected expired kid %s, got %s", wantKid, kid)
		}
		return &expiredKey.Private.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithoutClaimsValidation(),
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
	expNum, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("expected exp to be a number")
	}
	exp := time.Unix(int64(expNum), 0).UTC()

	if !exp.Equal(expiredKey.ExpiresAt.UTC()) {
		t.Fatalf("expected exp == expired key expiry, got %v want %v", exp, expiredKey.ExpiresAt.UTC())
	}
	if exp.After(time.Now().UTC()) {
		t.Fatalf("expected exp in the past, got %v", exp)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	store := newTestStore(t)
	s := NewServer(store)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
func TestAuthMissingBasicAuthReturns401(t *testing.T) {
	store := newTestStore(t)
	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	body := bytes.NewBufferString(`{"username":"userABC","password":"password123"}`)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthBadJSONReturns400(t *testing.T) {
	store := newTestStore(t)
	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	body := bytes.NewBufferString(`{bad json`)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth", body)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("userABC", "password123")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestJWKSMethodNotAllowed(t *testing.T) {
	store := newTestStore(t)
	s := NewServer(store)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
