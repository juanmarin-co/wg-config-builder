package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Name   string  `json:"name" yaml:"name"`
	Hosts  []Host  `json:"hosts" yaml:"hosts"`
	Routes []Route `json:"routes" yaml:"routes"`
}

type Host struct {
	Name            string        `json:"name" yaml:"name"`
	Endpoint        string        `json:"endpoint" yaml:"endpoint"`
	EgressInterface string        `json:"egressInterface" yaml:"egressInterface"`
	Interface       HostInterface `json:"interface" yaml:"interface"`
}

type HostInterface struct {
	Address string   `json:"address" yaml:"address"`
	DNS     []string `json:"dns" yaml:"dns"`
}

type Route struct {
	From                string   `json:"from" yaml:"from"`
	To                  string   `json:"to" yaml:"to"`
	AllowedIPs          []string `json:"allowedIps" yaml:"allowedIps"`
	PersistentKeepalive uint16   `json:"persistentKeepalive" yaml:"persistentKeepalive"`
}

func LoadConfiguration(path string) (Configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Configuration{}, fmt.Errorf("error reading config file %s: %w", path, err)
	}

	var configuration Configuration
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &configuration); err != nil {
			return Configuration{}, fmt.Errorf("error decoding JSON config file %s: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &configuration); err != nil {
			return Configuration{}, fmt.Errorf("error decoding YAML config file %s: %w", path, err)
		}
	default:
		return Configuration{}, fmt.Errorf("unsupported config file format: %s (supported: .json, .yaml, .yml)", ext)
	}

	return configuration, nil
}
