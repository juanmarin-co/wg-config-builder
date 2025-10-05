package internal

import (
	"fmt"
	"net"
)

func GenerateClientAddress(serverAddress string, clientIndex int) (string, error) {
	ip, _, err := net.ParseCIDR(serverAddress)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR format: %w", err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("serverAddress is not a valid IPv4 address")
	}

	ip4[3] = ip4[3] + byte(clientIndex)

	return fmt.Sprintf("%s/%d", ip4.String(), 32), nil
}
