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
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flags := parseFlags()

	configuration, err := loadAndValidateConfig(flags.configPath)
	if err != nil {
		return err
	}

	if err := ensureOutputDirectory(flags.baseOutputDir, configuration.Name); err != nil {
		return err
	}

	keyStore := internal.NewKeyStore(flags.keystorePath)

	keysets, err := loadHostKeysets(keyStore, configuration)
	if err != nil {
		return err
	}

	presharedKeys, err := loadPresharedKeys(keyStore, configuration)
	if err != nil {
		return err
	}

	wireguardConfig, err := buildWireguardConfig(configuration, keysets, presharedKeys)
	if err != nil {
		return err
	}

	if err := generateAndSaveConfigs(wireguardConfig, flags.baseOutputDir, configuration.Name); err != nil {
		return err
	}

	fmt.Printf("\n✓ All configurations written to: %s\n",
		filepath.Join(flags.baseOutputDir, configuration.Name))

	return nil
}

type cliFlags struct {
	configPath    string
	keystorePath  string
	baseOutputDir string
}

func parseFlags() cliFlags {
	configPath := flag.String("config", "config.json", "Path to the configuration file")
	keystorePath := flag.String("keystore", "keystore.json", "Path to the keystore file")
	baseOutputDir := flag.String("output", "generated", "Directory to output the generated configurations")
	flag.Parse()

	return cliFlags{
		configPath:    *configPath,
		keystorePath:  *keystorePath,
		baseOutputDir: *baseOutputDir,
	}
}

func loadAndValidateConfig(configPath string) (internal.Configuration, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return internal.Configuration{}, fmt.Errorf("configuration file not found: %s", configPath)
	}

	configuration, err := internal.LoadConfiguration(configPath)
	if err != nil {
		return internal.Configuration{}, fmt.Errorf("failed to load configuration from %s: %w", configPath, err)
	}

	if len(configuration.Hosts) == 0 {
		return internal.Configuration{}, fmt.Errorf("configuration contains no hosts")
	}

	fmt.Printf("Loaded configuration '%s' with %d hosts and %d routes\n",
		configuration.Name, len(configuration.Hosts), len(configuration.Routes))

	return configuration, nil
}

func ensureOutputDirectory(baseDir, networkName string) error {
	outputDir := filepath.Join(baseDir, networkName)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}
	return nil
}

func loadHostKeysets(keyStore *internal.KeyStore, config internal.Configuration) (map[string]wireguard.KeySet, error) {
	fmt.Println("\nGenerating cryptographic keys...")
	keysets := make(map[string]wireguard.KeySet, len(config.Hosts))

	for _, host := range config.Hosts {
		keyset, err := keyStore.Load(config.Name, host.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to load keys for host '%s': %w", host.Name, err)
		}
		keysets[host.Name] = keyset
		fmt.Printf("  ✓ %s\n", host.Name)
	}

	return keysets, nil
}

func loadPresharedKeys(keyStore *internal.KeyStore, config internal.Configuration) (map[string]string, error) {
	fmt.Println("\nGenerating preshared keys for peer pairs...")
	presharedKeys := make(map[string]string)

	for _, route := range config.Routes {
		pairKey := mapper.GetPairKey(route.From, route.To)

		if _, exists := presharedKeys[pairKey]; exists {
			continue
		}

		psk, err := keyStore.LoadPresharedKey(config.Name, pairKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load preshared key for pair %s: %w", pairKey, err)
		}

		presharedKeys[pairKey] = psk
		fmt.Printf("  ✓ %s ↔ %s\n", route.From, route.To)
	}

	return presharedKeys, nil
}

func buildWireguardConfig(config internal.Configuration, keysets map[string]wireguard.KeySet, presharedKeys map[string]string) (wireguard.Configuration, error) {
	fmt.Println("\nBuilding WireGuard configurations...")

	wgConfig, err := mapper.MapToWireguard(config, keysets, presharedKeys)
	if err != nil {
		return wireguard.Configuration{}, fmt.Errorf("failed to map configuration to WireGuard format: %w", err)
	}

	fmt.Printf("  ✓ Mapped %d hosts with peer relationships\n", len(config.Hosts))
	return wgConfig, nil
}

func generateAndSaveConfigs(wgConfig wireguard.Configuration, baseDir, networkName string) error {
	fmt.Println("\nGenerating configuration files...")

	rendered, err := wireguard.Render(wgConfig)
	if err != nil {
		return fmt.Errorf("failed to render configurations: %w", err)
	}

	outputDir := filepath.Join(baseDir, networkName)

	for hostName, configContent := range rendered.Hosts {
		configPath := filepath.Join(outputDir, fmt.Sprintf("%s.conf", hostName))

		if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
			return fmt.Errorf("failed to write config for host '%s': %w", hostName, err)
		}

		fmt.Printf("  ✓ %s.conf\n", hostName)
	}

	return nil
}
