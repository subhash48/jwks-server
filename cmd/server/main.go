package main

import (
	"log"
	"net/http"

	"github.com/subhash48/jwks-server/internal/handlers"
	"github.com/subhash48/jwks-server/internal/keystore"
)

func buildHandler(dbPath string) (http.Handler, func() error, error) {
	store, err := keystore.NewDBStore(dbPath)
	if err != nil {
		return nil, nil, err
	}
	closeFn := func() error { return store.Close() }
	s := handlers.NewServer(store)
	return s.Routes(), closeFn, nil
}

func main() {
	h, closeFn, err := buildHandler("./" + keystore.DBFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = closeFn() }()

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", h))
}
