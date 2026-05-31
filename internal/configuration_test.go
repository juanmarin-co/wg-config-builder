package internal

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExampleJSONConfigUsesCurrentSchema(t *testing.T) {
	config, err := LoadConfiguration(filepath.Join("..", "config.example.json"))
	require.NoError(t, err)
	require.NotEmpty(t, config.Name, "config name should be set")
	require.NotEmpty(t, config.Hosts, "config should define hosts")
	require.NotEmpty(t, config.Routes, "config should define routes")
}
