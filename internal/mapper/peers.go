package mapper

import (
	"encoding/base64"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func addRoutePeer(
	hosts map[string]wireguard.HostConfiguration,
	route routePlan,
	keysets map[string]wireguard.KeySet,
	presharedKey string,
) {
	allowedIPs := make([]string, 0, len(route.allowedIPs))
	for _, allowedIP := range route.allowedIPs {
		allowedIPs = append(allowedIPs, allowedIP.raw)
	}

	addPeer(hosts, route.from.Name, route.to.Name, route.to, keysets, presharedKey, allowedIPs, route.route.PersistentKeepalive)
}

func addReversePeer(
	hosts map[string]wireguard.HostConfiguration,
	route routePlan,
	keysets map[string]wireguard.KeySet,
	presharedKey string,
) {
	addPeer(hosts, route.to.Name, route.from.Name, route.from, keysets, presharedKey, []string{route.from.Interface.Address}, 0)
}

func addPeer(
	hosts map[string]wireguard.HostConfiguration,
	hostName string,
	peerName string,
	peerHost internal.Host,
	keysets map[string]wireguard.KeySet,
	presharedKey string,
	allowedIPs []string,
	persistentKeepalive uint16,
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

	peer.AllowedIPs = appendUnique(peer.AllowedIPs, allowedIPs...)
	if persistentKeepalive > 0 {
		peer.PersistentKeepalive = persistentKeepalive
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
