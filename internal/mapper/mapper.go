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
	hosts := make(map[string]wireguard.HostConfiguration)

	for _, host := range configuration.Hosts {
		if _, exists := hosts[host.Name]; exists {
			return wireguard.Configuration{}, fmt.Errorf("duplicate host %q", host.Name)
		}
		if host.Interface.Address == "" {
			return wireguard.Configuration{}, fmt.Errorf("missing interface address for host %q", host.Name)
		}

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

	for _, route := range configuration.Routes {
		fromHost := findHost(configuration.Hosts, route.From)
		if fromHost.Name == "" {
			return wireguard.Configuration{}, fmt.Errorf("route references unknown host %q", route.From)
		}

		toHost := findHost(configuration.Hosts, route.To)
		if toHost.Name == "" {
			return wireguard.Configuration{}, fmt.Errorf("route references unknown host %q", route.To)
		}
		if route.From == route.To {
			return wireguard.Configuration{}, fmt.Errorf("route cannot connect host %q to itself", route.From)
		}

		pairKey := GetPairKey(route.From, route.To)
		psk, exists := presharedKeys[pairKey]
		if !exists || psk == "" {
			return wireguard.Configuration{}, fmt.Errorf("missing preshared key for pair %s", pairKey)
		}

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
	hostConfig := hosts[hostName]
	peer, exists := hostConfig.Peers[peerName]

	if !exists {
		peerKeyset := keysets[peerName]
		peer = wireguard.HostPeerConfiguration{
			PublicKey:    base64.StdEncoding.EncodeToString(peerKeyset.PublicKey),
			PreSharedKey: presharedKey,
		}
	}

	if peerHost.Endpoint != "" {
		peer.Endpoint = peerHost.Endpoint
	}

	if len(route.AllowedIPs) > 0 {
		peer.AllowedIPs = appendUnique(peer.AllowedIPs, route.AllowedIPs...)
		if route.PersistentKeepalive > 0 {
			peer.PersistentKeepalive = route.PersistentKeepalive
		}
	} else {
		peer.AllowedIPs = appendUnique(peer.AllowedIPs, peerHost.Interface.Address)
	}

	hostConfig.Peers[peerName] = peer
	hosts[hostName] = hostConfig
}

func appendUnique(values []string, candidates ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(candidates))
	for _, value := range values {
		seen[value] = struct{}{}
	}

	for _, candidate := range candidates {
		if _, exists := seen[candidate]; exists {
			continue
		}
		values = append(values, candidate)
		seen[candidate] = struct{}{}
	}

	return values
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
			if isTrafficToSelf(allowedIP, host.Interface.Address) {
				continue
			}

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

func isTrafficToSelf(allowedIP string, hostAddress string) bool {
	return allowedIP == hostAddress
}
