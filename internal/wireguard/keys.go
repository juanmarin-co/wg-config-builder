package wireguard

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

type KeySet struct {
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
}

func GenerateKeySet() (KeySet, error) {
	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return KeySet{}, fmt.Errorf("error generating private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return KeySet{}, fmt.Errorf("error generating public key: %w", err)
	}

	return KeySet{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func GeneratePresharedKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("error generating preshared key: %w", err)
	}
	return key, nil
}
