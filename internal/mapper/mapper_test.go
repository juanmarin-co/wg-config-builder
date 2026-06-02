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

func TestMapToWireguardExampleJSONConfigUsesMapperSchema(t *testing.T) {
	config, err := internal.LoadConfiguration(filepath.Join("..", "..", "config.example.json"))
	require.NoError(t, err)

	_, err = mapToWireguardForTest(t, config)
	require.NoError(t, err)
}

func TestMapToWireguardAddsTerminalForwardDropsForEgressHost(t *testing.T) {
	result, err := mapToWireguardForTest(t, baseClientBastionConfig())
	require.NoError(t, err)

	bastion := result.Hosts["bastion-1"]
	assert.Equal(t, []string{
		"iptables -A FORWARD -i %i -j DROP",
		"iptables -A FORWARD -o %i -j DROP",
	}, bastion.Interface.PostUp[len(bastion.Interface.PostUp)-2:])
	assert.Equal(t, []string{
		"iptables -D FORWARD -i %i -j DROP",
		"iptables -D FORWARD -o %i -j DROP",
	}, bastion.Interface.PostDown[len(bastion.Interface.PostDown)-2:])
}

func TestMapToWireguardInvalidRouteModeReturnsError(t *testing.T) {
	config := baseClientBastionConfig()
	config.Routes[0].Mode = "bridged"

	_, err := mapToWireguardForTest(t, config)
	require.EqualError(t, err, `route client-1 -> bastion-1 has invalid mode "bridged" (supported: nat, routed)`)
}

func TestMapToWireguardRequiresAllowedIPs(t *testing.T) {
	config := baseClientBastionConfig()
	config.Routes[0].AllowedIPs = nil

	_, err := mapToWireguardForTest(t, config)
	require.EqualError(t, err, `route client-1 -> bastion-1 must define at least one allowedIps entry`)
}

func TestMapToWireguardRequiresAllowedIPsExplicitCanonicalCIDRNotation(t *testing.T) {
	tests := []struct {
		name          string
		allowedIP     string
		expectedError string
	}{
		{
			name:          "bare ip",
			allowedIP:     "10.10.0.1",
			expectedError: `route client-1 -> bastion-1 has invalid allowedIps entry "10.10.0.1": must be an explicit CIDR`,
		},
		{
			name:          "host bits set",
			allowedIP:     "10.10.0.1/24",
			expectedError: `route client-1 -> bastion-1 has invalid allowedIps entry "10.10.0.1/24": must be a canonical CIDR`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := baseClientBastionConfig()
			config.Routes[0].AllowedIPs = []string{tt.allowedIP}

			_, err := mapToWireguardForTest(t, config)
			require.EqualError(t, err, tt.expectedError)
		})
	}
}

func TestMapToWireguardRequiresSingleHostInterfaceCIDR(t *testing.T) {
	tests := []struct {
		name          string
		address       string
		expectedError string
	}{
		{
			name:          "missing cidr",
			address:       "172.20.0.2",
			expectedError: `invalid interface address for host "client-1": "172.20.0.2" must be an explicit single-host CIDR`,
		},
		{
			name:          "subnet cidr",
			address:       "172.20.0.0/24",
			expectedError: `invalid interface address for host "client-1": "172.20.0.0/24" must be a single-host CIDR (/32 for IPv4 or /128 for IPv6)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := baseClientBastionConfig()
			config.Hosts[1].Interface.Address = tt.address

			_, err := mapToWireguardForTest(t, config)
			require.EqualError(t, err, tt.expectedError)
		})
	}
}

func TestMapToWireguardRequiresEgressInterfaceForTransitRoute(t *testing.T) {
	config := baseClientBastionConfig()
	config.Hosts[0].EgressInterface = ""

	_, err := mapToWireguardForTest(t, config)
	require.EqualError(t, err, `route client-1 -> bastion-1 has transit allowedIps "10.10.0.0/16" but host "bastion-1" is missing egressInterface`)
}

func TestMapToWireguardDoesNotGenerateFirewallRulesWithoutTransitRoutes(t *testing.T) {
	config := baseClientBastionConfig()
	config.Hosts[0].EgressInterface = ""
	config.Routes[0].AllowedIPs = []string{"172.20.0.1/32"}

	result, err := mapToWireguardForTest(t, config)
	require.NoError(t, err)

	bastion := result.Hosts["bastion-1"]
	assert.Empty(t, bastion.Interface.PostUp)
	assert.Empty(t, bastion.Interface.PostDown)
}

func TestMapToWireguardTreatsCanonicalSelfTrafficAsDirect(t *testing.T) {
	config := internal.Configuration{
		Name: "canonical-self-mesh",
		Hosts: []internal.Host{
			{
				Name:            "bastion-1",
				EgressInterface: "eth0",
				Interface: internal.HostInterface{
					Address: "2001:db8::1/128",
				},
			},
			{
				Name: "client-1",
				Interface: internal.HostInterface{
					Address: "2001:db8::2/128",
				},
			},
		},
		Routes: []internal.Route{
			{
				From:       "client-1",
				To:         "bastion-1",
				AllowedIPs: []string{"2001:0db8:0:0:0:0:0:1/128"},
			},
		},
	}

	result, err := mapToWireguardForTest(t, config)
	require.NoError(t, err)

	bastion := result.Hosts["bastion-1"]
	assert.Empty(t, bastion.Interface.PostUp)
	assert.Empty(t, bastion.Interface.PostDown)
}

func TestMapToWireguardRejectsIPv6TransitRoutes(t *testing.T) {
	config := baseClientBastionConfig()
	config.Routes[0].AllowedIPs = []string{"2001:db8:10::/64"}

	_, err := mapToWireguardForTest(t, config)
	require.EqualError(t, err, `route client-1 -> bastion-1 uses IPv6 transit network "2001:db8:10::/64", but IPv6 forwarding is not supported yet`)
}

func TestMapToWireguardIPv4TransitRequiresIPv4SourceAddress(t *testing.T) {
	config := baseClientBastionConfig()
	config.Hosts[0].Interface.Address = "fd00::1/128"
	config.Hosts[1].Interface.Address = "fd00::2/128"

	_, err := mapToWireguardForTest(t, config)
	require.EqualError(t, err, `route client-1 -> bastion-1 uses IPv4 transit network "10.10.0.0/16" but source host "client-1" address "fd00::2/128" is not IPv4`)
}

func TestMapToWireguardAllowsOverlappingAllowedIPsForDifferentSources(t *testing.T) {
	config := baseClientBastionConfig()
	config.Hosts = append(config.Hosts, internal.Host{
		Name: "client-2",
		Interface: internal.HostInterface{
			Address: "172.20.0.3/32",
		},
	})
	config.Routes = append(config.Routes, internal.Route{
		From:       "client-2",
		To:         "bastion-1",
		AllowedIPs: []string{"10.10.0.0/16"},
	})

	_, err := mapToWireguardForTest(t, config)
	require.NoError(t, err)
}

func TestMapToWireguardRejectsOverlappingAllowedIPsForSameSource(t *testing.T) {
	tests := []struct {
		name          string
		secondPeer    string
		expectedError string
	}{
		{
			name:          "same peer",
			secondPeer:    "bastion-1",
			expectedError: `route client-1 -> bastion-1 allowedIps "10.1.0.0/16" overlaps with route client-1 -> bastion-1 allowedIps "10.0.0.0/8"`,
		},
		{
			name:          "different peer",
			secondPeer:    "bastion-2",
			expectedError: `route client-1 -> bastion-2 allowedIps "10.1.0.0/16" overlaps with route client-1 -> bastion-1 allowedIps "10.0.0.0/8"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := baseClientBastionConfig()
			config.Hosts = append(config.Hosts, internal.Host{
				Name:            "bastion-2",
				Endpoint:        "10.0.0.2:51820",
				EgressInterface: "eth0",
				Interface: internal.HostInterface{
					Address: "172.20.0.3/32",
				},
			})
			config.Routes = []internal.Route{
				{
					From:       "client-1",
					To:         "bastion-1",
					AllowedIPs: []string{"10.0.0.0/8"},
				},
				{
					From:       "client-1",
					To:         tt.secondPeer,
					AllowedIPs: []string{"10.1.0.0/16"},
				},
			}

			_, err := mapToWireguardForTest(t, config)
			require.EqualError(t, err, tt.expectedError)
		})
	}
}

func baseClientBastionConfig() internal.Configuration {
	return internal.Configuration{
		Name: "test-mesh",
		Hosts: []internal.Host{
			{
				Name:            "bastion-1",
				Endpoint:        "10.0.0.1:51820",
				EgressInterface: "eth0",
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
}

func mapToWireguardForTest(t *testing.T, config internal.Configuration) (wireguard.Configuration, error) {
	t.Helper()

	keysets := make(map[string]wireguard.KeySet)
	for _, host := range config.Hosts {
		keySet, err := wireguard.GenerateKeySet()
		require.NoError(t, err, "failed to generate keyset for host %s", host.Name)
		keysets[host.Name] = keySet
	}

	presharedKeys := make(map[string]string)
	for _, route := range config.Routes {
		pairKey := GetPairKey(route.From, route.To)
		if _, exists := presharedKeys[pairKey]; exists {
			continue
		}
		psk, err := wireguard.GeneratePresharedKey()
		require.NoError(t, err, "failed to generate preshared key for pair %s", pairKey)
		presharedKeys[pairKey] = base64.StdEncoding.EncodeToString(psk)
	}

	return MapToWireguard(config, keysets, presharedKeys)
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
				Name:            "bastion-1",
				EgressInterface: "eth0",
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
