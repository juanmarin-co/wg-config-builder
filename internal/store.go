package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

type KeyStore struct {
	path string
}

type persistentData struct {
	KeySets map[string]wireguard.KeySet `json:"keySets"`
}

func NewKeyStore(path string) *KeyStore {
	return &KeyStore{
		path: path,
	}
}

func (store *KeyStore) Load(seed string, name string) (wireguard.KeySet, error) {
	keyId := calculateKeyId(seed, name)

	data, err := store.loadFromDisk()
	if err != nil {
		return wireguard.KeySet{}, fmt.Errorf("failed to load from disk: %w", err)
	}

	if keySet, exists := data.KeySets[keyId]; exists {
		return keySet, nil
	}

	keySet, err := wireguard.GenerateKeySet()
	if err != nil {
		return wireguard.KeySet{}, fmt.Errorf("failed to generate key set: %w", err)
	}

	data.KeySets[keyId] = keySet
	if err := store.saveToDisk(data); err != nil {
		return wireguard.KeySet{}, fmt.Errorf("failed to save keystore: %w", err)
	}

	return keySet, nil
}

func (store *KeyStore) loadFromDisk() (persistentData, error) {
	if store.path == "" {
		return persistentData{}, fmt.Errorf("no path specified for keystore")
	}

	fileData, err := os.ReadFile(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, return empty data
			return persistentData{
				KeySets: make(map[string]wireguard.KeySet),
			}, nil
		}

		return persistentData{}, fmt.Errorf("failed to read keystore file: %w", err)
	}

	var data persistentData
	if err := json.Unmarshal(fileData, &data); err != nil {
		return persistentData{}, fmt.Errorf("failed to unmarshal keystore data: %w", err)
	}

	if data.KeySets == nil {
		data.KeySets = make(map[string]wireguard.KeySet)
	}

	return data, nil
}

func (store *KeyStore) saveToDisk(data persistentData) error {
	if store.path == "" {
		return fmt.Errorf("no path specified for keystore")
	}

	// Ensure directory exists
	dir := filepath.Dir(store.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keystore data: %w", err)
	}

	// Write to temporary file first, then rename for atomic operation
	tempPath := store.path + ".tmp"
	if err := os.WriteFile(tempPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write temporary keystore file: %w", err)
	}

	if err := os.Rename(tempPath, store.path); err != nil {
		os.Remove(tempPath) // Clean up temp file on error
		return fmt.Errorf("failed to rename temporary keystore file: %w", err)
	}

	return nil
}

func calculateKeyId(seed string, name string) string {
	hash := sha256.New()
	hash.Write([]byte(seed))
	hash.Write([]byte(name))

	return hex.EncodeToString(hash.Sum(nil))
}
