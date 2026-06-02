package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanmarin-co/wg-config-builder/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAndValidateConfigRejectsInvalidMapperConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{
  "name": "invalid-mode-mesh",
  "hosts": [
    {
      "name": "bastion-1",
      "endpoint": "10.0.0.1:51820",
      "egressInterface": "eth0",
      "interface": { "address": "172.20.0.1/32" }
    },
    {
      "name": "client-1",
      "interface": { "address": "172.20.0.2/32" }
    }
  ],
  "routes": [
    {
      "from": "client-1",
      "to": "bastion-1",
      "mode": "bridged",
      "allowedIps": ["10.10.0.0/16"]
    }
  ]
}`), 0600))

	_, err := loadAndValidateConfig(configPath)

	require.EqualError(t, err, `invalid configuration: route client-1 -> bastion-1 has invalid mode "bridged" (supported: nat, routed)`)
}

func TestEnsureOutputDirectoryRejectsNetworkPathTraversal(t *testing.T) {
	rootDir := t.TempDir()
	baseDir := filepath.Join(rootDir, "generated")

	err := ensureOutputDirectory(baseDir, "../escape-network")

	assert.Error(t, err)
	_, statErr := os.Stat(filepath.Join(rootDir, "escape-network"))
	assert.True(t, os.IsNotExist(statErr), "path traversal target should not exist")
}

func TestGenerateAndSaveConfigsPrintsHostsInSortedOrder(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "generated")
	networkName := "safe-network"
	require.NoError(t, ensureOutputDirectory(baseDir, networkName))

	wgConfig := wireguard.Configuration{
		Hosts: map[string]wireguard.HostConfiguration{
			"z-host": testHostConfiguration(),
			"a-host": testHostConfiguration(),
			"m-host": testHostConfiguration(),
			"b-host": testHostConfiguration(),
			"y-host": testHostConfiguration(),
		},
	}

	for range 100 {
		var err error
		output := captureStdout(t, func() {
			err = generateAndSaveConfigs(wgConfig, baseDir, networkName)
		})
		require.NoError(t, err)

		assertTextBefore(t, output, "a-host.conf", "b-host.conf")
		assertTextBefore(t, output, "b-host.conf", "m-host.conf")
		assertTextBefore(t, output, "m-host.conf", "y-host.conf")
		assertTextBefore(t, output, "y-host.conf", "z-host.conf")
	}
}

func TestGenerateAndSaveConfigsRejectsHostPathTraversal(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "generated")
	networkName := "safe-network"
	require.NoError(t, ensureOutputDirectory(baseDir, networkName))

	wgConfig := wireguard.Configuration{
		Hosts: map[string]wireguard.HostConfiguration{
			"../escape": {
				Interface: wireguard.HostInterfaceConfiguration{
					Address:    "172.20.0.2/32",
					PrivateKey: "test-private-key",
				},
				Peers: map[string]wireguard.HostPeerConfiguration{},
			},
		},
	}

	err := generateAndSaveConfigs(wgConfig, baseDir, networkName)

	assert.Error(t, err)
	assert.NoFileExists(t, filepath.Join(baseDir, "escape.conf"))
	_, statErr := os.Stat(filepath.Join(baseDir, networkName, "..", "escape.conf"))
	assert.True(t, os.IsNotExist(statErr), "path traversal target should not exist")
}

func testHostConfiguration() wireguard.HostConfiguration {
	return wireguard.HostConfiguration{
		Interface: wireguard.HostInterfaceConfiguration{
			Address:    "172.20.0.2/32",
			PrivateKey: "test-private-key",
		},
		Peers: map[string]wireguard.HostPeerConfiguration{},
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = writer
	fn()
	os.Stdout = originalStdout

	require.NoError(t, writer.Close())
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	return string(output)
}

func assertTextBefore(t *testing.T, text, first, second string) {
	t.Helper()

	firstIndex := strings.Index(text, first)
	require.NotEqual(t, -1, firstIndex, "text missing %q:\n%s", first, text)

	secondIndex := strings.Index(text, second)
	require.NotEqual(t, -1, secondIndex, "text missing %q:\n%s", second, text)

	require.Less(t, firstIndex, secondIndex, "expected %q before %q in:\n%s", first, second, text)
}
