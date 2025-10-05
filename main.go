package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func main() {
	configuration, err := internal.LoadConfiguration("config.json")
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}

	keyStore := internal.NewKeyStore("keystore.json")

	serverKeySet, err := keyStore.Load(configuration.Seed, fmt.Sprintf("server-%s", configuration.Server.Name))
	if err != nil {
		fmt.Printf("Error loading server keys: %v\n", err)
		return
	}

	fmt.Printf("Server %s keyset: %+v\n", configuration.Server.Name, serverKeySet)

	// Build server configuration
	serverConfig := wireguard.ServerConfiguration{
		PublicIP:   configuration.Server.PublicIP,
		Address:    configuration.Server.Address,
		ListenPort: configuration.Server.ListenPort,
		KeySet:     serverKeySet,
	}

	var clientConfigs []wireguard.ClientConfiguration
	for i, client := range configuration.Clients {
		clientKeySet, err := keyStore.Load(configuration.Seed, fmt.Sprintf("client-%s", client.Name))
		if err != nil {
			fmt.Printf("Error loading client %s keys: %v\n", client.Name, err)
			return
		}

		clientAddress, err := internal.GenerateClientAddress(configuration.Server.Address, i+1)
		if err != nil {
			fmt.Printf("Error generating address for client %s: %v\n", client.Name, err)
			return
		}

		clientConfig := wireguard.ClientConfiguration{
			Address:    clientAddress,
			KeySet:     clientKeySet,
			AllowedIPs: client.AllowedIps,
		}
		clientConfigs = append(clientConfigs, clientConfig)
	}

	// Build wireguard configuration
	wgConfig := wireguard.Configuration{
		Server:  serverConfig,
		Clients: clientConfigs,
	}

	fmt.Printf("WireGuard Configuration:\n")
	fmt.Printf("Server: %+v\n", wgConfig.Server)
	fmt.Printf("Clients: %+v\n", wgConfig.Clients)

	rendered, err := wireguard.Render(wgConfig)
	if err != nil {
		fmt.Printf("Error rendering configuration: %v\n", err)
		return
	}

	// Create output directory
	outputDir := filepath.Join("generated", configuration.Seed)
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	// Write server configuration
	serverConfigPath := filepath.Join(outputDir, "wg0.conf")
	err = os.WriteFile(serverConfigPath, []byte(rendered.ServerConfig), 0600)
	if err != nil {
		fmt.Printf("Error writing server config: %v\n", err)
		return
	}
	fmt.Printf("Server configuration written to: %s\n", serverConfigPath)

	// Write client configurations
	for clientName, clientConfig := range rendered.ClientConfig {
		clientConfigPath := filepath.Join(outputDir, fmt.Sprintf("%s.conf", clientName))
		err = os.WriteFile(clientConfigPath, []byte(clientConfig), 0600)
		if err != nil {
			fmt.Printf("Error writing client config %s: %v\n", clientName, err)
			return
		}
		fmt.Printf("Client configuration written to: %s\n", clientConfigPath)
	}

	fmt.Printf("All configurations written to directory: %s\n", outputDir)
}
