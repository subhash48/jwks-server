package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/golang-jwt/jwt/v5"

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

func TestAuthReturnsValidJWTWithKid(t *testing.T) {
	store := newTestStore(t)
	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp := postAuth(t, ts.URL+"/auth")
	defer resp.Body.Close()

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenStr := string(tokenBytes)

	validKeys, _ := store.GetValidKeys(context.Background())
	pub := &validKeys[0].Private.PublicKey
	wantKid := strconv.FormatInt(validKeys[0].KID, 10)

	parsed, err := jwt.Parse(tokenStr, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		if kid != wantKid {
			t.Fatalf("expected kid %s, got %s", wantKid, kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	if err != nil || !parsed.Valid {
		t.Fatal("expected token to be valid")
	}
}

func TestExpiredAuthUsesExpiredKeyAndExpiredExp(t *testing.T) {
	store := newTestStore(t)
	s := NewServer(store)
	ts := httptest.NewServer(s.Routes())
	defer ts.Close()

	resp := postAuth(t, ts.URL+"/auth?expired=1")
	defer resp.Body.Close()

	tokenBytes, _ := io.ReadAll(resp.Body)
	tokenStr := string(tokenBytes)

	expiredKey, _ := store.GetSigningKey(context.Background(), true)
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

	if err != nil || !parsed.Valid {
		t.Fatal("expected expired token signature to be valid")
	}
}
