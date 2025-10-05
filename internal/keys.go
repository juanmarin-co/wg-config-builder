package internal

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

type KeySet struct {
	PresharedKey []byte `json:"presharedKey"`
	PrivateKey   []byte `json:"privateKey"`
	PublicKey    []byte `json:"publicKey"`
}

func GenerateKeySet() (KeySet, error) {
	presharedKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, presharedKey); err != nil {
		return KeySet{}, fmt.Errorf("error generating preshared key: %w", err)
	}

	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return KeySet{}, fmt.Errorf("error generating private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return KeySet{}, fmt.Errorf("error generating public key: %w", err)
	}

	return KeySet{
		PresharedKey: presharedKey,
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
	}, nil
}
