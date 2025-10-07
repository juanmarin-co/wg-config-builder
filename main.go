package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to the configuration file")
	keystorePath := flag.String("keystore", "keystore.json", "Path to the keystore file")
	flag.Parse()

	configuration, err := internal.LoadConfiguration(*configPath)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}

	keyStore := internal.NewKeyStore(*keystorePath)

	for _, server := range configuration.Servers {
		fmt.Printf("Generating configuration for server: %s\n", server.Name)

		serverKeySet, err := keyStore.Load(configuration.Seed, fmt.Sprintf("server-%s", server.Name))
		if err != nil {
			fmt.Printf("Error loading server keys for %s: %v\n", server.Name, err)
			continue // Continue to the next server
		}

		serverConfig := wireguard.ServerConfiguration{
			PublicIP:   server.PublicIP,
			Address:    server.Address,
			ListenPort: server.ListenPort,
			KeySet:     serverKeySet,
			Interface:  server.Interface,
			DNS:        server.DNS,
		}

		clientConfigs := make(map[string]wireguard.ClientConfiguration)
		clientCounter := 0
		for _, client := range configuration.Clients {
			isClientForServer := false
			for _, serverName := range client.Servers {
				if serverName == server.Name {
					isClientForServer = true
					break
				}
			}

			if !isClientForServer {
				continue
			}

			clientKeySet, err := keyStore.Load(configuration.Seed, fmt.Sprintf("client-%s", client.Name))
			if err != nil {
				fmt.Printf("Error loading client %s keys: %v\n", client.Name, err)
				continue
			}

			clientCounter++
			clientAddress, err := internal.GenerateClientAddress(server.Address, clientCounter)
			if err != nil {
				fmt.Printf("Error generating address for client %s on server %s: %v\n", client.Name, server.Name, err)
				continue
			}

			clientConfig := wireguard.ClientConfiguration{
				Address:    clientAddress,
				KeySet:     clientKeySet,
				AllowedIPs: client.AllowedIps,
			}

			clientConfigs[client.Name] = clientConfig
		}

		if len(clientConfigs) == 0 {
			fmt.Printf("No clients for server %s, skipping.\n", server.Name)
			continue
		}

		wgConfig := wireguard.Configuration{
			Server:  serverConfig,
			Clients: clientConfigs,
		}

		rendered, err := wireguard.Render(wgConfig)
		if err != nil {
			fmt.Printf("Error rendering configuration for server %s: %v\n", server.Name, err)
			continue
		}

		outputDir := filepath.Join("generated", configuration.Seed, server.Name)
		err = os.MkdirAll(outputDir, 0755)
		if err != nil {
			fmt.Printf("Error creating output directory for server %s: %v\n", server.Name, err)
			continue
		}

		serverConfigPath := filepath.Join(outputDir, "server.conf")
		err = os.WriteFile(serverConfigPath, []byte(rendered.ServerConfig), 0600)
		if err != nil {
			fmt.Printf("Error writing server config for %s: %v\n", server.Name, err)
			continue
		}
		fmt.Printf("Server configuration for %s written to: %s\n", server.Name, serverConfigPath)

		for clientName, clientConfigContent := range rendered.ClientConfig {
			clientConfigPath := filepath.Join(outputDir, fmt.Sprintf("client-%s.conf", clientName))
			err = os.WriteFile(clientConfigPath, []byte(clientConfigContent), 0600)
			if err != nil {
				fmt.Printf("Error writing client config %s for server %s: %v\n", clientName, server.Name, err)
				continue
			}
			fmt.Printf("Client configuration %s for server %s written to: %s\n", clientName, server.Name, clientConfigPath)
		}
		fmt.Printf("All configurations for server %s written to directory: %s\n", server.Name, outputDir)
	}
}
