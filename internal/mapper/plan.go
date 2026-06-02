package mapper

import (
	"fmt"
	"net/netip"

	"github.com/juanmarin-co/wg-config-builder/internal"
)

type routeMode string

const (
	routeModeNAT    routeMode = "nat"
	routeModeRouted routeMode = "routed"
)

type configurationPlan struct {
	hosts  []internal.Host
	routes []routePlan
}

type routePlan struct {
	route      internal.Route
	from       internal.Host
	to         internal.Host
	mode       routeMode
	allowedIPs []allowedIPPlan
}

type allowedIPPlan struct {
	raw     string
	transit bool
}

type seenAllowedIP struct {
	prefix netip.Prefix
	route  internal.Route
	value  string
}

func ValidateConfiguration(configuration internal.Configuration) error {
	_, err := buildConfigurationPlan(configuration)
	return err
}

func buildConfigurationPlan(configuration internal.Configuration) (configurationPlan, error) {
	plan := configurationPlan{
		hosts: make([]internal.Host, 0, len(configuration.Hosts)),
	}
	hostByName := make(map[string]internal.Host, len(configuration.Hosts))
	hostAddressByName := make(map[string]netip.Prefix, len(configuration.Hosts))

	for _, host := range configuration.Hosts {
		if _, exists := hostByName[host.Name]; exists {
			return configurationPlan{}, fmt.Errorf("duplicate host %q", host.Name)
		}
		if host.Interface.Address == "" {
			return configurationPlan{}, fmt.Errorf("missing interface address for host %q", host.Name)
		}

		hostAddress, err := parseHostInterfaceAddress(host)
		if err != nil {
			return configurationPlan{}, err
		}

		if host.Endpoint != "" && extractPortFromEndpoint(host.Endpoint) == 0 {
			return configurationPlan{}, fmt.Errorf("invalid endpoint for host %q: %s", host.Name, host.Endpoint)
		}

		plan.hosts = append(plan.hosts, host)
		hostByName[host.Name] = host
		hostAddressByName[host.Name] = hostAddress
	}

	routes, err := buildRoutePlans(configuration.Routes, hostByName, hostAddressByName)
	if err != nil {
		return configurationPlan{}, err
	}
	plan.routes = routes

	return plan, nil
}

func parseHostInterfaceAddress(host internal.Host) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(host.Interface.Address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid interface address for host %q: %q must be an explicit single-host CIDR", host.Name, host.Interface.Address)
	}

	if prefix.Bits() != prefix.Addr().BitLen() {
		return netip.Prefix{}, fmt.Errorf("invalid interface address for host %q: %q must be a single-host CIDR (/32 for IPv4 or /128 for IPv6)", host.Name, host.Interface.Address)
	}

	return prefix.Masked(), nil
}

func buildRoutePlans(
	routes []internal.Route,
	hosts map[string]internal.Host,
	hostAddresses map[string]netip.Prefix,
) ([]routePlan, error) {
	seenBySource := make(map[string][]seenAllowedIP)
	plans := make([]routePlan, 0, len(routes))

	for _, route := range routes {
		fromHost, exists := hosts[route.From]
		if !exists {
			return nil, fmt.Errorf("route references unknown host %q", route.From)
		}

		toHost, exists := hosts[route.To]
		if !exists {
			return nil, fmt.Errorf("route references unknown host %q", route.To)
		}

		if route.From == route.To {
			return nil, fmt.Errorf("route cannot connect host %q to itself", route.From)
		}

		mode, err := parseRouteMode(route)
		if err != nil {
			return nil, err
		}

		if len(route.AllowedIPs) == 0 {
			return nil, fmt.Errorf("route %s -> %s must define at least one allowedIps entry", route.From, route.To)
		}

		fromAddress := hostAddresses[route.From]
		toAddress := hostAddresses[route.To]
		plan := routePlan{
			route:      route,
			from:       fromHost,
			to:         toHost,
			mode:       mode,
			allowedIPs: make([]allowedIPPlan, 0, len(route.AllowedIPs)),
		}

		for _, allowedIP := range route.AllowedIPs {
			allowedPrefix, err := parseAllowedIP(route, allowedIP)
			if err != nil {
				return nil, err
			}

			if err := validateAllowedIPDoesNotOverlap(route, allowedIP, allowedPrefix, seenBySource[route.From]); err != nil {
				return nil, err
			}

			entry := allowedIPPlan{
				raw:     allowedIP,
				transit: !isSelfPrefix(allowedPrefix, toAddress),
			}

			if entry.transit {
				if err := validateTransitAllowedIP(plan, fromAddress, allowedPrefix, entry); err != nil {
					return nil, err
				}
			}

			seenBySource[route.From] = append(seenBySource[route.From], seenAllowedIP{
				prefix: allowedPrefix,
				route:  route,
				value:  allowedIP,
			})
			plan.allowedIPs = append(plan.allowedIPs, entry)
		}

		plans = append(plans, plan)
	}

	return plans, nil
}

func parseRouteMode(route internal.Route) (routeMode, error) {
	switch route.Mode {
	case "", string(routeModeNAT):
		return routeModeNAT, nil
	case string(routeModeRouted):
		return routeModeRouted, nil
	default:
		return "", fmt.Errorf("route %s -> %s has invalid mode %q (supported: nat, routed)", route.From, route.To, route.Mode)
	}
}

func parseAllowedIP(route internal.Route, allowedIP string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(allowedIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("route %s -> %s has invalid allowedIps entry %q: must be an explicit CIDR", route.From, route.To, allowedIP)
	}

	masked := prefix.Masked()
	if prefix != masked {
		return netip.Prefix{}, fmt.Errorf("route %s -> %s has invalid allowedIps entry %q: must be a canonical CIDR", route.From, route.To, allowedIP)
	}

	return masked, nil
}

func validateAllowedIPDoesNotOverlap(
	route internal.Route,
	allowedIP string,
	allowedPrefix netip.Prefix,
	seen []seenAllowedIP,
) error {
	for _, previous := range seen {
		if allowedPrefix.Overlaps(previous.prefix) {
			return fmt.Errorf("route %s -> %s allowedIps %q overlaps with route %s -> %s allowedIps %q", route.From, route.To, allowedIP, previous.route.From, previous.route.To, previous.value)
		}
	}

	return nil
}

func validateTransitAllowedIP(route routePlan, fromAddress netip.Prefix, allowedPrefix netip.Prefix, entry allowedIPPlan) error {
	if route.to.EgressInterface == "" {
		return fmt.Errorf("route %s -> %s has transit allowedIps %q but host %q is missing egressInterface", route.from.Name, route.to.Name, entry.raw, route.to.Name)
	}

	if !allowedPrefix.Addr().Is4() {
		return fmt.Errorf("route %s -> %s uses IPv6 transit network %q, but IPv6 forwarding is not supported yet", route.from.Name, route.to.Name, entry.raw)
	}

	if !fromAddress.Addr().Is4() {
		return fmt.Errorf("route %s -> %s uses IPv4 transit network %q but source host %q address %q is not IPv4", route.from.Name, route.to.Name, entry.raw, route.from.Name, route.from.Interface.Address)
	}

	return nil
}

func isSelfPrefix(prefix netip.Prefix, hostPrefix netip.Prefix) bool {
	return prefix == hostPrefix
}
