package mapper

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func MapToWireguard(
	configuration internal.Configuration,
	keysets map[string]wireguard.KeySet,
	presharedKeys map[string]string,
) (wireguard.Configuration, error) {
	plan, err := buildConfigurationPlan(configuration)
	if err != nil {
		return wireguard.Configuration{}, err
	}

	hosts := make(map[string]wireguard.HostConfiguration)
	for _, host := range plan.hosts {
		keyset, exists := keysets[host.Name]
		if !exists {
			return wireguard.Configuration{}, fmt.Errorf("missing keyset for host %q", host.Name)
		}

		interfaceConfig, err := buildInterface(host, keyset)
		if err != nil {
			return wireguard.Configuration{}, err
		}

		hosts[host.Name] = wireguard.HostConfiguration{
			Interface: interfaceConfig,
			Peers:     make(map[string]wireguard.HostPeerConfiguration),
		}
	}

	for _, route := range plan.routes {
		pairKey := GetPairKey(route.from.Name, route.to.Name)
		psk, exists := presharedKeys[pairKey]
		if !exists || psk == "" {
			return wireguard.Configuration{}, fmt.Errorf("missing preshared key for pair %s", pairKey)
		}

		addRoutePeer(hosts, route, keysets, psk)
		addReversePeer(hosts, route, keysets, psk)
	}

	for _, host := range plan.hosts {
		addForwardingRules(hosts, host, plan.routes)
	}

	return wireguard.Configuration{Hosts: hosts}, nil
}

func buildInterface(host internal.Host, keyset wireguard.KeySet) (wireguard.HostInterfaceConfiguration, error) {
	interfaceConfig := wireguard.HostInterfaceConfiguration{
		Address:    host.Interface.Address,
		PrivateKey: base64.StdEncoding.EncodeToString(keyset.PrivateKey),
	}

	if host.Endpoint != "" {
		port := extractPortFromEndpoint(host.Endpoint)
		if port == 0 {
			return wireguard.HostInterfaceConfiguration{}, fmt.Errorf("invalid endpoint for host %q: %s", host.Name, host.Endpoint)
		}
		interfaceConfig.ListenPort = port
	}

	if len(host.Interface.DNS) > 0 {
		interfaceConfig.DNS = host.Interface.DNS
	}

	return interfaceConfig, nil
}

func extractPortFromEndpoint(endpoint string) uint16 {
	_, portString, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0
	}

	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return 0
	}

	return uint16(port)
}

func GetPairKey(host1, host2 string) string {
	if host1 < host2 {
		return host1 + ":" + host2
	}
	return host2 + ":" + host1
}
