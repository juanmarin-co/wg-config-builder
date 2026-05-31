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
				require.EqualError(t, err, tc.ExpectedError)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, tc.ExpectedOutput, "expectedOutput must not be nil when no error is expected")

			fillGeneratedKeys(tc.ExpectedOutput, result)

			assert.Equal(t, tc.ExpectedOutput, &result, "output mismatch")
		})
	}
}

func TestMapToWireguardDuplicateHostReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "duplicate-host-mesh",
		Hosts: []internal.Host{
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.2/32",
				},
			},
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.3/32",
				},
			},
		},
	}

	keySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	_, err = MapToWireguard(config, map[string]wireguard.KeySet{"client-1": keySet}, nil)
	require.EqualError(t, err, `duplicate host "client-1"`)
}

func TestMapToWireguardSelfRouteReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "self-route-mesh",
		Hosts: []internal.Host{
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.2/32",
				},
			},
		},
		Routes: []internal.Route{
			{
				From:       "client-1",
				To:         "client-1",
				AllowedIPs: []string{"10.10.0.0/16"},
			},
		},
	}

	keySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	keysets := map[string]wireguard.KeySet{"client-1": keySet}
	presharedKeys := map[string]string{GetPairKey("client-1", "client-1"): "test-preshared-key"}

	_, err = MapToWireguard(config, keysets, presharedKeys)
	require.EqualError(t, err, `route cannot connect host "client-1" to itself`)
}

func TestMapToWireguardUnknownRouteHostReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "unknown-host-mesh",
		Hosts: []internal.Host{
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.2/32",
				},
			},
		},
		Routes: []internal.Route{
			{
				From:       "client-1",
				To:         "missing-bastion",
				AllowedIPs: []string{"10.10.0.0/16"},
			},
		},
	}

	keySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	keysets := map[string]wireguard.KeySet{
		"client-1": keySet,
	}
	presharedKeys := map[string]string{
		GetPairKey("client-1", "missing-bastion"): "test-preshared-key",
	}

	require.NotPanics(t, func() {
		_, err := MapToWireguard(config, keysets, presharedKeys)
		require.EqualError(t, err, `route references unknown host "missing-bastion"`)
	})
}

func TestExtractPortFromEndpointSupportsIPv6(t *testing.T) {
	port := extractPortFromEndpoint("[2001:db8::1]:51820")

	assert.Equal(t, uint16(51820), port)
}

func TestMapToWireguardMissingHostAddressReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "missing-host-address-mesh",
		Hosts: []internal.Host{
			{Name: "client-1"},
		},
	}

	keySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	_, err = MapToWireguard(config, map[string]wireguard.KeySet{"client-1": keySet}, nil)
	require.EqualError(t, err, `missing interface address for host "client-1"`)
}

func TestMapToWireguardMissingHostKeysetReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "missing-keyset-mesh",
		Hosts: []internal.Host{
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.2/32",
				},
			},
		},
	}

	_, err := MapToWireguard(config, map[string]wireguard.KeySet{}, nil)

	require.EqualError(t, err, `missing keyset for host "client-1"`)
}

func TestMapToWireguardMissingPresharedKeyReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "missing-preshared-key-mesh",
		Hosts: []internal.Host{
			{
				Name: "bastion-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.1/32",
				},
			},
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "172.20.0.2/32",
				},
			},
		},
		Routes: []internal.Route{
			{
				From:       "client-1",
				To:         "bastion-1",
				AllowedIPs: []string{"10.10.0.0/16"},
			},
		},
	}

	bastionKeySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)
	clientKeySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	keysets := map[string]wireguard.KeySet{
		"bastion-1": bastionKeySet,
		"client-1":  clientKeySet,
	}

	_, err = MapToWireguard(config, keysets, map[string]string{})
	require.EqualError(t, err, `missing preshared key for pair bastion-1:client-1`)
}

func TestMapToWireguardInvalidEndpointPortReturnsError(t *testing.T) {
	config := internal.Configuration{
		Name: "invalid-endpoint-mesh",
		Hosts: []internal.Host{
			{
				Name:     "bastion-1",
				Endpoint: "10.0.0.1:not-a-port",
				Interface: internal.HostInterface{
					Address: "172.20.0.1/32",
				},
			},
		},
	}

	keySet, err := wireguard.GenerateKeySet()
	require.NoError(t, err)

	_, err = MapToWireguard(config, map[string]wireguard.KeySet{"bastion-1": keySet}, nil)
	require.EqualError(t, err, `invalid endpoint for host "bastion-1": 10.0.0.1:not-a-port`)
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
