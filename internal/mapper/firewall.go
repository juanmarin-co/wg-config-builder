package mapper

import (
	"fmt"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func addForwardingRules(
	hosts map[string]wireguard.HostConfiguration,
	host internal.Host,
	routes []routePlan,
) {
	var postUp []string
	var postDown []string
	hasTransitRoutes := false

	for _, route := range routes {
		if route.to.Name != host.Name {
			continue
		}

		fromAddress := route.from.Interface.Address

		for _, allowedIP := range route.allowedIPs {
			if !allowedIP.transit {
				continue
			}
			hasTransitRoutes = true

			if route.mode == routeModeNAT {
				postUp = append(postUp, fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -d %s -o %s -j MASQUERADE", fromAddress, allowedIP.raw, host.EgressInterface))
				postDown = append(postDown, fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -d %s -o %s -j MASQUERADE", fromAddress, allowedIP.raw, host.EgressInterface))
			}

			postUp = append(postUp,
				fmt.Sprintf("iptables -A FORWARD -i %%i -s %s -d %s -j ACCEPT", fromAddress, allowedIP.raw),
				fmt.Sprintf("iptables -A FORWARD -i %s -s %s -d %s -j ACCEPT", host.EgressInterface, allowedIP.raw, fromAddress),
			)
			postDown = append(postDown,
				fmt.Sprintf("iptables -D FORWARD -i %%i -s %s -d %s -j ACCEPT", fromAddress, allowedIP.raw),
				fmt.Sprintf("iptables -D FORWARD -i %s -s %s -d %s -j ACCEPT", host.EgressInterface, allowedIP.raw, fromAddress),
			)
		}
	}

	if !hasTransitRoutes {
		return
	}

	// Make the per-route allow rules restrictive even when the host's default
	// FORWARD policy is ACCEPT, without changing the global chain policy.
	postUp = append(postUp,
		"iptables -A FORWARD -i %i -j DROP",
		"iptables -A FORWARD -o %i -j DROP",
	)
	postDown = append(postDown,
		"iptables -D FORWARD -i %i -j DROP",
		"iptables -D FORWARD -o %i -j DROP",
	)

	hostConfig := hosts[host.Name]
	hostConfig.Interface.PostUp = postUp
	hostConfig.Interface.PostDown = postDown
	hosts[host.Name] = hostConfig
}
