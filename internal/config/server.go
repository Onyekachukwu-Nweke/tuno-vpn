package config

import (
	"fmt"
)

// ServerConfig holds all the configuration for the Tuno VPN server
type ServerConfig struct {
	// Network settings
	ListenAddr string `mapstructure:"listen_addr"` // Address to listen on (host:port)
	TunDevice  string `mapstructure:"tun_device"`  // TUN device name (e.g., tun0)
	TunIP      string `mapstructure:"tun_ip"`      // TUN device IP with CIDR (e.g., 10.0.0.1/24)
	MTU        int    `mapstructure:"mtu"`         // Maximum Transmission Unit

	// TLS settings
	CertFile string `mapstructure:"cert_file"` // Path to TLS certificate file
	KeyFile  string `mapstructure:"key_file"`  // Path to TLS key file

	// TODO: Authentication settings (for future use)
	AuthMode     string `mapstructure:"auth_mode"`     // Authentication mode (none, password, certificate)
	PasswordFile string `mapstructure:"password_file"` // Path to password file

	// Logging settings
	LogLevel string `mapstructure:"log_level"` // Log level (debug, info, warn, error)
	LogFile  string `mapstructure:"log_file"`  // Path to log file

	// Advanced settings
	EnableIPv6 bool `mapstructure:"enable_ipv6"` // Enable IPv6 support
	EnableNAT  bool `mapstructure:"enable_nat"`  // Enable NAT for client traffic
	MaxClients int  `mapstructure:"max_clients"` // Maximum number of clients
}

// LoadServerConfig loads the server configuration from a file
func LoadServerConfig(cfgFile string) (*ServerConfig, error) {
	// Default configuration
	defaults := map[string]interface{}{
		"listen_addr": "0.0.0.0:8080",
		"tun_device":  "tun0",
		"tun_ip":      "10.0.0.1/24",
		"mtu":         1400,
		"log_level":   "info",
		"enable_ipv6": false,
		"enable_nat":  true,
		"max_clients": 10,
		"auth_mode":   "none",
	}

	// Load configuration from file
	v, err := loadConfigFile(cfgFile, defaults, "server")
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}

	// Map to config struct
	var config ServerConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error parsing config: %v", err)
	}

	// Expand file paths
	if config.CertFile, err = expandPath(config.CertFile); err != nil {
		return nil, fmt.Errorf("invalid cert file path: %v", err)
	}
	if config.KeyFile, err = expandPath(config.KeyFile); err != nil {
		return nil, fmt.Errorf("invalid key file path: %v", err)
	}
	if config.PasswordFile, err = expandPath(config.PasswordFile); err != nil {
		return nil, fmt.Errorf("invalid password file path: %v", err)
	}
	if config.LogFile, err = expandPath(config.LogFile); err != nil {
		return nil, fmt.Errorf("invalid log file path: %v", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}
