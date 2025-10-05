package internal

import (
	"encoding/json"
	"fmt"
	"os"
)

type Configuration struct {
	Seed    string   `json:"seed"`
	Server  Server   `json:"server"`
	Clients []Client `json:"clients"`
}

type Server struct {
	Name       string   `json:"name"`
	PublicIP   string   `json:"publicIp"`
	Address    string   `json:"address"`
	ListenPort uint16   `json:"listenPort"`
	Interface  string   `json:"interface"`
	DNS        []string `json:"dns"`
}

type Client struct {
	Name       string   `json:"name"`
	AllowedIps []string `json:"allowedIps"`
}

func LoadConfiguration(path string) (Configuration, error) {
	file, err := os.Open(path)
	if err != nil {
		return Configuration{}, fmt.Errorf("error opening config file %s: %w", path, err)
	}

	defer file.Close()

	var configuration Configuration
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&configuration); err != nil {
		return Configuration{}, fmt.Errorf("error decoding config file %s: %w", path, err)
	}

	return configuration, nil
}
