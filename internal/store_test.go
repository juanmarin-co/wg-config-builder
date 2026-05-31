package internal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
	"github.com/stretchr/testify/require"
)

func TestKeyStoreLoadFindsLegacyKeyIds(t *testing.T) {
	keySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	data := persistentData{
		KeySets: map[string]wireguard.KeySet{
			calculateLegacyTestKeyId("seed", "host"): keySet,
		},
		PresharedKeys: map[string]string{},
	}

	keystorePath := filepath.Join(t.TempDir(), "keystore.json")
	jsonData, err := json.Marshal(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keystorePath, jsonData, 0600))

	loaded, err := NewKeyStore(keystorePath).Load("seed", "host")

	require.NoError(t, err)
	require.Equal(t, keySet, loaded)
}

func TestKeyStoreLoadPresharedKeyFindsLegacyKeyIds(t *testing.T) {
	const psk = "test-preshared-key"

	data := persistentData{
		KeySets: map[string]wireguard.KeySet{},
		PresharedKeys: map[string]string{
			calculateLegacyTestKeyId("seed", "host-a:host-b"): psk,
		},
	}

	keystorePath := filepath.Join(t.TempDir(), "keystore.json")
	jsonData, err := json.Marshal(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keystorePath, jsonData, 0600))

	loaded, err := NewKeyStore(keystorePath).LoadPresharedKey("seed", "host-a:host-b")

	require.NoError(t, err)
	require.Equal(t, psk, loaded)
}

func TestCalculateKeyIdDoesNotCollideWhenSeedAndNameBoundariesDiffer(t *testing.T) {
	first := calculateKeyId("ab", "c")
	second := calculateKeyId("a", "bc")

	if first == second {
		t.Fatalf("expected different key IDs for different seed/name pairs, got collision %q", first)
	}
}

func calculateLegacyTestKeyId(seed string, name string) string {
	hash := sha256.New()
	hash.Write([]byte(seed))
	hash.Write([]byte(name))

	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
