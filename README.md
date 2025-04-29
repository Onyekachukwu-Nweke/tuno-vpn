# Tuno VPN

A modular VPN system written in Go with encryption, process safety features, split tunneling capabilities, and optional peer-to-peer support.

## Features (Planned)

- **Core Tunnel Engine**: Virtual TUN interface with TLS encryption
- **VPN Kill Switch**: Automatically kill processes or disable networking if VPN connection drops
- **Traffic Splitter**: Route specific traffic through VPN or direct connection
- **Decentralized P2P Networking**: Optional mesh networking with libp2p (future milestone)

## Project Status

This project is under active development, currently working on Milestone 1:

- ✅ Create virtual interface with `netstack`
- ✅ Encrypt traffic over `tls.Conn` between two nodes
- ✅ Pass packets from TUN → TLS → TUN
- ✅ CLI: `tuno client` and `tuno server`

## Installation

### Prerequisites

- Go 1.21 or higher
- Linux or macOS (Windows support planned)
- Root/sudo access (required for creating TUN devices)

### Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/tuno-vpn.git
cd tuno-vpn

# Build the project
make build

# Generate TLS certificates for testing
make genkeys

# Install (optional)
sudo make install
```

## Usage

### Server Setup

1. Edit the server configuration:

```bash
vi configs/server.yaml  # or /etc/tuno/server.yaml if installed
```

2. Run the server:

```bash
sudo tuno server
# or if not installed:
sudo ./build/tuno server
```

### Client Setup

1. Edit the client configuration:

```bash
vi configs/client.yaml  # or /etc/tuno/client.yaml if installed
```

2. Run the client:

```bash
sudo tuno client
# or if not installed:
sudo ./build/tuno client
```

### Configuration Options

Both server and client configurations have extensive options. See the sample configuration files in `configs/` directory for details.

## Architecture

Tuno VPN consists of several modular components:

### Core Tunnel Engine

The core tunneling functionality creates a virtual TUN interface that captures traffic, encrypts it using TLS, and sends it to the server. The server decrypts the traffic and forwards it to its destination.

### TLS Encryption

All traffic between client and server is encrypted using TLS 1.2+ with strong cipher suites. The client can verify the server's certificate to prevent man-in-the-middle attacks.

### TUN Interface

The TUN interface captures IP packets at layer 3, allowing Tuno to handle routing and encryption without requiring more complex layer 2 framing.

## Directory Structure

```
tuno-vpn/
├── cmd/                         # Command-line applications
│   ├── tunocli/                 # Main CLI application
│   ├── tunoserver/              # Standalone server binary
│   └── tunoclient/              # Standalone client binary
├── internal/                    # Private application code
│   ├── cipher/                  # Encryption/decryption implementation
│   ├── tunnel/                  # Core tunneling functionality
│   ├── config/                  # Configuration management
│   └── logger/                  # Logging functionality
├── pkg/                         # Public libraries
│   ├── protocol/                # VPN protocol implementation
│   └── netutil/                 # Network utilities
├── api/                         # API definitions
├── configs/                     # Configuration file templates
├── scripts/                     # Helper scripts
├── build/                       # Build artifacts
├── test/                        # Integration tests
└── docs/                        # Documentation
```

## Future Milestones

### Milestone 2: VPN Kill Switch
- Monitor VPN connection status in background daemon
- Configurable kill rules for processes and network access
- Firewall lockdown with `nftables` when VPN connection drops

### Milestone 3: Split Tunnel Control
- User configuration for routes/domains to tunnel
- Modify system route table or iptables rules
- Per-application routing

### Milestone 4: P2P VPN Mode
- Integrate libp2p for signaling and connection
- Encode TUN packets into libp2p streams
- Support multiple peers in a mesh network

## Security Considerations

### TLS Configuration
Tuno VPN uses strong TLS 1.2+ cipher suites and requires certificate validation by default. For testing, you can disable certificate validation with the `skip_verify` option, but this is not recommended for production use.

### Permissions
Running a VPN requires administrative privileges to create and manage TUN devices. Always review the code before running with elevated privileges.

### Authentication
The current milestone implements basic TLS authentication. Future releases will add support for password and certificate-based authentication.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [gVisor](https://github.com/google/gvisor) for the `netstack` implementation
- [vishvananda/netlink](https://github.com/vishvananda/netlink) for network interface manipulation
- [Go TUN/TAP](https://github.com/songgao/water) for inspiration on TUN device handling