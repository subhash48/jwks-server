package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/subhash48/jwks-server/internal/keystore"
)

func TestBuildHandlerCreatesDBAndServesJWKS(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, keystore.DBFileName)

	h, closeFn, err := buildHandler(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db file to exist: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBuildHandlerBadPath(t *testing.T) {
	tmp := t.TempDir()
	// passing a directory path as DB path should fail
	_, _, err := buildHandler(tmp)
	if err == nil {
		t.Fatal("expected error for bad db path")
	}
}
