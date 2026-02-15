package main

import (
	"log"
	"net/http"

	"github.com/subhash48/jwks-server/internal/handlers"
	"github.com/subhash48/jwks-server/internal/keystore"
)

func main() {
	store, err := keystore.NewStore()
	if err != nil {
		log.Fatal(err)
	}

	s := handlers.NewServer(store)

	log.Println("JWKS server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", s.Routes()))
}

