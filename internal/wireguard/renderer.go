package wireguard

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type RenderResult struct {
	ServerConfig string
	ClientConfig map[string]string
}

func Render(configuration Configuration) (RenderResult, error) {
	result := RenderResult{
		ClientConfig: make(map[string]string),
	}

	// Render server configuration
	serverConfig, err := renderServerConfig(configuration)
	if err != nil {
		return result, fmt.Errorf("failed to render server config: %w", err)
	}
	result.ServerConfig = serverConfig

	// Render client configurations
	for i, client := range configuration.Clients {
		clientName := fmt.Sprintf("client%d", i+1)
		clientConfig, err := renderClientConfig(configuration.Server, client)
		if err != nil {
			return result, fmt.Errorf("failed to render client %s config: %w", clientName, err)
		}
		result.ClientConfig[clientName] = clientConfig
	}

	return result, nil
}

func renderServerConfig(config Configuration) (string, error) {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", config.Server.Address))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", config.Server.ListenPort))

	privateKey := base64.StdEncoding.EncodeToString(config.Server.KeySet.PrivateKey)
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))

	for _, client := range config.Clients {
		sb.WriteString("\n[Peer]\n")

		publicKey := base64.StdEncoding.EncodeToString(client.KeySet.PublicKey)
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", publicKey))

		presharedKey := base64.StdEncoding.EncodeToString(client.KeySet.PresharedKey)
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", presharedKey))

		sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", client.Address))
	}

	return sb.String(), nil
}

func renderClientConfig(server ServerConfiguration, client ClientConfiguration) (string, error) {
	var sb strings.Builder

	// Client interface section
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("Address = %s\n", client.Address))

	privateKey := base64.StdEncoding.EncodeToString(client.KeySet.PrivateKey)
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))

	// Server peer section
	sb.WriteString("\n[Peer]\n")

	publicKey := base64.StdEncoding.EncodeToString(server.KeySet.PublicKey)
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", publicKey))

	presharedKey := base64.StdEncoding.EncodeToString(client.KeySet.PresharedKey)
	sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", presharedKey))

	sb.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", server.PublicIP, server.ListenPort))
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(client.AllowedIPs, ", ")))
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String(), nil
}
