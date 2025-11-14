package mapper

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type TestCase struct {
	Name           string                   `yaml:"name"`
	Input          internal.Configuration   `yaml:"input"`
	ExpectedOutput *wireguard.Configuration `yaml:"expectedOutput"`
	ExpectedError  string                   `yaml:"expectedError"`
}

func TestMapToWireguard(t *testing.T) {
	yamlFiles, err := filepath.Glob("testdata/*.yaml")
	require.NoError(t, err, "failed to find yaml files in testdata")
	require.NotEmpty(t, yamlFiles, "no yaml files found in testdata directory")

	var testCases []TestCase
	for _, yamlFile := range yamlFiles {
		data, err := os.ReadFile(yamlFile)
		require.NoError(t, err, "failed to read test file %s", yamlFile)

		var cases []TestCase
		err = yaml.Unmarshal(data, &cases)
		require.NoError(t, err, "failed to unmarshal test file %s", yamlFile)

		testCases = append(testCases, cases...)
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			keysets := make(map[string]wireguard.KeySet)
			for _, host := range tc.Input.Hosts {
				keySet, err := wireguard.GenerateKeySet()
				require.NoError(t, err, "failed to generate keyset for host %s", host.Name)
				keysets[host.Name] = keySet
			}

			presharedKeys := make(map[string]string)
			for _, route := range tc.Input.Routes {
				pairKey := GetPairKey(route.From, route.To)
				if _, exists := presharedKeys[pairKey]; !exists {
					psk, err := wireguard.GeneratePresharedKey()
					require.NoError(t, err, "failed to generate preshared key for pair %s", pairKey)
					presharedKeys[pairKey] = base64.StdEncoding.EncodeToString(psk)
				}
			}

			result, err := MapToWireguard(tc.Input, keysets, presharedKeys)

			if tc.ExpectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.ExpectedError)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tc.ExpectedOutput, "expectedOutput must not be nil when no error is expected")

			fillGeneratedKeys(tc.ExpectedOutput, result)

			assert.Equal(t, tc.ExpectedOutput, &result, "output mismatch")
		})
	}
}

func fillGeneratedKeys(expected *wireguard.Configuration, actual wireguard.Configuration) {
	for hostName, expectedHost := range expected.Hosts {
		actualHost := actual.Hosts[hostName]

		expectedHost.Interface.PrivateKey = actualHost.Interface.PrivateKey

		for peerName, expectedPeer := range expectedHost.Peers {
			actualPeer := actualHost.Peers[peerName]
			expectedPeer.PublicKey = actualPeer.PublicKey
			expectedPeer.PreSharedKey = actualPeer.PreSharedKey
			expectedHost.Peers[peerName] = expectedPeer
		}

		expected.Hosts[hostName] = expectedHost
	}
}
