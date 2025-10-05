package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/juanmarin-co/wg-config-builder/internal"
)

func main() {
	configuration, err := internal.LoadConfiguration("config.json")
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}

	seedHash := sha256.Sum256([]byte(configuration.Seed))

	keyStore := internal.NewKeyStore("keystore.json")

	serverKeySet, err := keyStore.Load(seedHash[:], configuration.Server.Name)
	if err != nil {
		fmt.Printf("Error loading server keys: %v\n", err)
		return
	}

	fmt.Printf("Server %s keyset: %+v\n", configuration.Server.Name, serverKeySet)
}
