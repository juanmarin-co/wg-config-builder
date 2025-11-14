package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/juanmarin-co/wg-config-builder/internal"
	"github.com/juanmarin-co/wg-config-builder/internal/mapper"
	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to the configuration file")
	keystorePath := flag.String("keystore", "keystore.json", "Path to the keystore file")
	baseOutputDir := flag.String("output", "generated", "Directory to output the generated configurations")
	flag.Parse()

	configuration, err := internal.LoadConfiguration(*configPath)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}

	outputDir := filepath.Join(*baseOutputDir, configuration.Name)
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	keyStore := internal.NewKeyStore(*keystorePath)

	// Process hosts
	fmt.Println("Processing hosts...")
	for index, host := range configuration.Hosts {
		fmt.Printf("  Host %d: %s\n", index+1, host.Name)
	}

	// Load keysets into a map
	fmt.Println("\nLoading keysets...")
	keysets := make(map[string]wireguard.KeySet)
	for _, host := range configuration.Hosts {
		keyset, err := keyStore.Load(configuration.Name, host.Name)
		if err != nil {
			fmt.Printf("Error loading keys for host %s: %v\n", host.Name, err)
			return
		}
		keysets[host.Name] = keyset
	}

	// Load preshared keys for each route pair
	fmt.Println("\nLoading preshared keys...")
	presharedKeys := make(map[string]string)
	for _, route := range configuration.Routes {
		pairKey := mapper.GetPairKey(route.From, route.To)
		if _, exists := presharedKeys[pairKey]; !exists {
			psk, err := keyStore.LoadPresharedKey(configuration.Name, pairKey)
			if err != nil {
				fmt.Printf("Error loading preshared key for pair %s: %v\n", pairKey, err)
				return
			}
			presharedKeys[pairKey] = psk
		}
	}

	// Map internal.Configuration to wireguard.Configuration
	fmt.Println("\nMapping configuration to WireGuard format...")
	wgConfig, err := mapper.MapToWireguard(configuration, keysets, presharedKeys)
	if err != nil {
		fmt.Printf("Error mapping configuration: %v\n", err)
		return
	}
	fmt.Printf("✓ Successfully mapped %d hosts and %d routes\n", len(configuration.Hosts), len(configuration.Routes))

	// Render all configurations
	rendered, err := wireguard.Render(wgConfig)
	if err != nil {
		fmt.Printf("Error rendering configurations: %v\n", err)
		return
	}

	// Save each host configuration
	for hostName, configContent := range rendered.Hosts {
		configPath := filepath.Join(outputDir, fmt.Sprintf("%s.conf", hostName))
		err = os.WriteFile(configPath, []byte(configContent), 0600)
		if err != nil {
			fmt.Printf("Error saving config for host %s: %v\n", hostName, err)
			return
		}
		fmt.Printf("Configuration written to: %s\n", configPath)
	}

	fmt.Printf("\nAll configurations written to directory: %s\n", outputDir)
}
