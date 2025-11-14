# WireGuard Config Builder

> Define your WireGuard mesh network in YAML, get production-ready configs

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Transform a simple network topology definition into complete WireGuard configurations with automatic key management, routing rules, and NAT setup.

## What It Does

You define **who** needs to connect to **what** in a YAML file. The tool generates:

- Complete WireGuard config files for each host
- Cryptographic keypairs and preshared keys (stored and reused)
- iptables rules for routing and NAT on gateway hosts
- Proper peer relationships so traffic flows both ways

## Common Use Cases

- **Remote access VPN** - Developers connect to office/cloud networks from anywhere
- **Multi-region access** - Route traffic to different cloud regions through separate gateways
- **Site-to-site VPN** - Connect office networks together
- **Kubernetes access** - Secure access to cluster services and pods
- **Split-tunnel setups** - Route only specific networks through VPN, not all traffic
- **High availability** - Multiple gateways for redundancy and failover

## Quick Start

**1. Install**

```bash
git clone https://github.com/yourusername/wg-config-builder.git
cd wg-config-builder
go build
```

**2. Define your network**

Create `my-network.yaml`:

```yaml
name: my-network
hosts:
  # Gateway server with a public IP
  - name: gateway
    endpoint: 203.0.113.10:51820
    egressInterface: eth0
    interface:
      address: 10.200.0.1/32

  # Your laptop
  - name: laptop
    interface:
      address: 10.200.0.10/32
      dns:
        - 8.8.8.8

routes:
  # Laptop connects to gateway to reach private networks
  - from: laptop
    to: gateway
    persistentKeepalive: 25
    allowedIps:
      - 10.1.0.0/16  # Private network behind gateway
```

**3. Generate configs**

```bash
./wg-config-builder -config my-network.yaml
```

This creates `generated/my-network/gateway.conf` and `generated/my-network/laptop.conf`.

**4. Deploy and start**

```bash
# On gateway server
scp generated/my-network/gateway.conf root@gateway:/etc/wireguard/wg0.conf
ssh root@gateway "wg-quick up wg0"

# On laptop
sudo cp generated/my-network/laptop.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

## Understanding Routes

A **route** defines one direction of connectivity:

```yaml
- from: laptop
  to: gateway
  allowedIps:
    - 10.1.0.0/16
```

This means: "Laptop should be able to reach `10.1.0.0/16` by going through gateway."

The tool automatically creates the peer relationship on both sides:
- Laptop's config gets gateway as a peer
- Gateway's config gets laptop as a peer

**About `allowedIps`:**
- These are networks/IPs reachable **through** the peer
- Traffic to these addresses will be sent through the WireGuard tunnel
- It does NOT automatically include the peer's own IP
- Only add the peer's IP if you need direct access to that host itself

## Configuration Reference

### Host Types

**Gateway/Bastion** (has public IP, routes traffic):
```yaml
- name: gateway
  endpoint: 203.0.113.10:51820     # Public IP:port
  egressInterface: eth0             # Interface for internet/NAT
  interface:
    address: 10.200.0.1/32          # WireGuard tunnel IP
```

**Client** (connects to gateways):
```yaml
- name: client
  interface:
    address: 10.200.0.10/32         # WireGuard tunnel IP
    dns:                            # Optional DNS servers
      - 8.8.8.8
```

### Route Fields

```yaml
- from: client              # Source host
  to: gateway               # Destination host
  persistentKeepalive: 25   # Optional: keep connection alive (for NAT)
  allowedIps:               # Networks reachable through this route
    - 10.0.0.0/8
```

## What Gets Generated

For each host, you get a complete WireGuard config:

**Gateway config includes:**
- WireGuard interface setup
- Private key (auto-generated)
- Listen port from endpoint
- iptables rules for routing and NAT
- Peer sections for each client

**Client config includes:**
- WireGuard interface setup
- Private key (auto-generated)
- DNS servers
- Peer sections with gateway endpoints

All keys are stored in `keystore.json` and reused on subsequent runs.

## Command Line Options

```bash
./wg-config-builder [options]

Options:
  -config string
        Path to the configuration file (default "config.json")
  -keystore string
        Path to the keystore file (default "keystore.json")
  -output string
        Directory to output the generated configurations (default "generated")
```

## Requirements

- Go 1.21 or later
- WireGuard tools on deployment hosts (`wg-quick`)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for your changes
4. Use [Conventional Commits](https://www.conventionalcommits.org/)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details

---

**Questions?** Check [config.example.yaml](config.example.yaml) for more examples or open an issue.