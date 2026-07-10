package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigurationReadsInterfaceMTU(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`name: test-mesh
hosts:
  - name: client-1
    interface:
      address: 172.20.0.2/32
      mtu: 1380
`), 0o600)
	require.NoError(t, err)

	config, err := LoadConfiguration(path)
	require.NoError(t, err)
	require.Len(t, config.Hosts, 1)
	require.Equal(t, uint16(1380), config.Hosts[0].Interface.MTU)
}

func TestExampleJSONConfigUsesCurrentSchema(t *testing.T) {
	config, err := LoadConfiguration(filepath.Join("..", "config.example.json"))
	require.NoError(t, err)
	require.NotEmpty(t, config.Name, "config name should be set")
	require.NotEmpty(t, config.Hosts, "config should define hosts")
	require.NotEmpty(t, config.Routes, "config should define routes")
}
