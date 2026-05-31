package wireguard

import (
	"fmt"
	"sort"
	"strings"
)

type RenderResult struct {
	Hosts map[string]string
}

func Render(configuration Configuration) (RenderResult, error) {
	result := RenderResult{
		Hosts: make(map[string]string),
	}

	for hostName, hostConfig := range configuration.Hosts {
		configStr, err := renderHostConfig(hostName, hostConfig)
		if err != nil {
			return result, fmt.Errorf("failed to render host %s config: %w", hostName, err)
		}

		result.Hosts[hostName] = configStr
	}

	return result, nil
}

func renderHostConfig(hostName string, config HostConfiguration) (string, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Host: %s\n", hostName))
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", config.Interface.Address))

	if config.Interface.ListenPort > 0 {
		sb.WriteString(fmt.Sprintf("ListenPort = %d\n", config.Interface.ListenPort))
	}

	if len(config.Interface.DNS) > 0 {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(config.Interface.DNS, ", ")))
	}

	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", config.Interface.PrivateKey))

	for _, postUp := range config.Interface.PostUp {
		sb.WriteString(fmt.Sprintf("PostUp = %s\n", postUp))
	}

	for _, postDown := range config.Interface.PostDown {
		sb.WriteString(fmt.Sprintf("PostDown = %s\n", postDown))
	}

	peerNames := make([]string, 0, len(config.Peers))
	for peerName := range config.Peers {
		peerNames = append(peerNames, peerName)
	}
	sort.Strings(peerNames)

	for _, peerName := range peerNames {
		peer := config.Peers[peerName]
		sb.WriteString(fmt.Sprintf("\n# Peer: %s\n", peerName))
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PreSharedKey))

		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", ")))
		}

		if peer.PersistentKeepalive > 0 {
			sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}
	}

	return sb.String(), nil
}
