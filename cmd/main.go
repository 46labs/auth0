package main

import (
	"log"

	"github.com/46labs/auth0/pkg/config"
	"github.com/46labs/auth0/pkg/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
}
