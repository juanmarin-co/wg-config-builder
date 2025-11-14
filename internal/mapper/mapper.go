package mapper

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func MapToWireguard(
	configuration internal.Configuration,
	keysets map[string]wireguard.KeySet,
	presharedKeys map[string]string,
) (wireguard.Configuration, error) {
	hosts := make(map[string]wireguard.HostConfiguration)

	for _, host := range configuration.Hosts {
		keyset := keysets[host.Name]

		hosts[host.Name] = wireguard.HostConfiguration{
			Interface: buildInterface(host, keyset),
			Peers:     make(map[string]wireguard.HostPeerConfiguration),
		}
	}

	for _, route := range configuration.Routes {
		fromHost := findHost(configuration.Hosts, route.From)
		toHost := findHost(configuration.Hosts, route.To)

		pairKey := GetPairKey(route.From, route.To)
		psk := presharedKeys[pairKey]

		addPeerToHost(hosts, route.From, route.To, toHost, keysets, psk, route)
		addPeerToHost(hosts, route.To, route.From, fromHost, keysets, psk, internal.Route{})
	}

	for _, host := range configuration.Hosts {
		if host.EgressInterface != "" {
			addForwardingRules(hosts, host, configuration.Routes)
		}
	}

	return wireguard.Configuration{Hosts: hosts}, nil
}

func buildInterface(host internal.Host, keyset wireguard.KeySet) wireguard.HostInterfaceConfiguration {
	interfaceConfig := wireguard.HostInterfaceConfiguration{
		Address:    host.Interface.Address,
		PrivateKey: base64.StdEncoding.EncodeToString(keyset.PrivateKey),
	}

	if host.Endpoint != "" {
		port := extractPortFromEndpoint(host.Endpoint)
		interfaceConfig.ListenPort = port
	}

	if len(host.Interface.DNS) > 0 {
		interfaceConfig.DNS = host.Interface.DNS
	}

	return interfaceConfig
}

func extractPortFromEndpoint(endpoint string) uint16 {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return 0
	}

	var port uint16
	fmt.Sscanf(parts[1], "%d", &port)
	return port
}

func findHost(hosts []internal.Host, name string) internal.Host {
	for _, host := range hosts {
		if host.Name == name {
			return host
		}
	}
	return internal.Host{}
}

func GetPairKey(host1, host2 string) string {
	if host1 < host2 {
		return host1 + ":" + host2
	}
	return host2 + ":" + host1
}

func addPeerToHost(
	hosts map[string]wireguard.HostConfiguration,
	hostName string,
	peerName string,
	peerHost internal.Host,
	keysets map[string]wireguard.KeySet,
	presharedKey string,
	route internal.Route,
) {
	if _, exists := hosts[hostName].Peers[peerName]; exists {
		return
	}

	peerKeyset := keysets[peerName]
	peer := wireguard.HostPeerConfiguration{
		PublicKey:    base64.StdEncoding.EncodeToString(peerKeyset.PublicKey),
		PreSharedKey: presharedKey,
	}

	if peerHost.Endpoint != "" {
		peer.Endpoint = peerHost.Endpoint
	}

	if len(route.AllowedIPs) > 0 {
		peer.AllowedIPs = route.AllowedIPs
		peer.PersistentKeepalive = route.PersistentKeepalive
	} else {
		peer.AllowedIPs = []string{peerHost.Interface.Address}
	}

	hostConfig := hosts[hostName]
	hostConfig.Peers[peerName] = peer
	hosts[hostName] = hostConfig
}

func addForwardingRules(
	hosts map[string]wireguard.HostConfiguration,
	host internal.Host,
	routes []internal.Route,
) {
	var postUp []string
	var postDown []string

	postUp = append(postUp, fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", host.EgressInterface))
	postDown = append(postDown, fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", host.EgressInterface))

	for _, route := range routes {
		if route.To != host.Name {
			continue
		}

		fromHostConfig := hosts[route.From]
		fromAddress := fromHostConfig.Interface.Address

		for _, allowedIP := range route.AllowedIPs {
			postUp = append(postUp,
				fmt.Sprintf("iptables -A FORWARD -i %%i -s %s -d %s -j ACCEPT", fromAddress, allowedIP),
				fmt.Sprintf("iptables -A FORWARD -i %s -s %s -d %s -j ACCEPT", host.EgressInterface, allowedIP, fromAddress),
			)
			postDown = append(postDown,
				fmt.Sprintf("iptables -D FORWARD -i %%i -s %s -d %s -j ACCEPT", fromAddress, allowedIP),
				fmt.Sprintf("iptables -D FORWARD -i %s -s %s -d %s -j ACCEPT", host.EgressInterface, allowedIP, fromAddress),
			)
		}
	}

	hostConfig := hosts[host.Name]
	hostConfig.Interface.PostUp = postUp
	hostConfig.Interface.PostDown = postDown
	hosts[host.Name] = hostConfig
}
