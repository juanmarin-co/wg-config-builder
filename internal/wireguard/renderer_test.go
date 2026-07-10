package wireguard

import (
	"strings"
	"testing"
)

func TestRenderIncludesConfiguredInterfaceMTU(t *testing.T) {
	result, err := Render(Configuration{
		Hosts: map[string]HostConfiguration{
			"client-1": {
				Interface: HostInterfaceConfiguration{
					Address:    "172.20.0.2/32",
					MTU:        1380,
					PrivateKey: "test-private-key",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if !strings.Contains(result.Hosts["client-1"], "MTU = 1380\n") {
		t.Fatalf("rendered config missing configured MTU:\n%s", result.Hosts["client-1"])
	}
}

func TestRenderHostConfigSortsPeersByName(t *testing.T) {
	config := HostConfiguration{
		Interface: HostInterfaceConfiguration{
			Address:    "172.20.0.1/32",
			PrivateKey: "test-private-key",
		},
		Peers: map[string]HostPeerConfiguration{
			"z-peer": {PublicKey: "z-public-key", PreSharedKey: "z-psk"},
			"a-peer": {PublicKey: "a-public-key", PreSharedKey: "a-psk"},
			"m-peer": {PublicKey: "m-public-key", PreSharedKey: "m-psk"},
		},
	}

	for range 100 {
		rendered, err := renderHostConfig("host-1", config)
		if err != nil {
			t.Fatalf("renderHostConfig returned error: %v", err)
		}

		assertPeerBefore(t, rendered, "a-peer", "m-peer")
		assertPeerBefore(t, rendered, "m-peer", "z-peer")
	}
}

func assertPeerBefore(t *testing.T, rendered, first, second string) {
	t.Helper()

	firstIndex := strings.Index(rendered, "# Peer: "+first)
	if firstIndex == -1 {
		t.Fatalf("rendered config missing peer %q:\n%s", first, rendered)
	}

	secondIndex := strings.Index(rendered, "# Peer: "+second)
	if secondIndex == -1 {
		t.Fatalf("rendered config missing peer %q:\n%s", second, rendered)
	}

	if firstIndex > secondIndex {
		t.Fatalf("expected peer %q to render before %q:\n%s", first, second, rendered)
	}
}
