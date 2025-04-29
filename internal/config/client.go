package config

import (
	"fmt"
)

// ClientConfig holds all the configuration for the Tuno VPN client
type ClientConfig struct {
	// Network settings
	ServerAddr string `mapstructure:"server_addr"` // Server address (host:port)
	TunDevice  string `mapstructure:"tun_device"`  // TUN device name (e.g., tun0)
	TunIP      string `mapstructure:"tun_ip"`      // TUN device IP with CIDR (e.g., 10.0.0.2/24)
	MTU        int    `mapstructure:"mtu"`         // Maximum Transmission Unit

	// TLS settings
	CACertFile string `mapstructure:"ca_cert_file"` // Path to CA certificate file for server verification
	ClientCert string `mapstructure:"client_cert"`  // Path to client certificate (for cert auth mode)
	ClientKey  string `mapstructure:"client_key"`   // Path to client key (for cert auth mode)
	SkipVerify bool   `mapstructure:"skip_verify"`  // Skip server certificate verification (not recommended)

	// Authentication settings
	AuthMode string `mapstructure:"auth_mode"` // Authentication mode (none, password, certificate)
	Username string `mapstructure:"username"`  // Username for password authentication
	Password string `mapstructure:"password"`  // Password for password authentication

	// Advanced settings
	Reconnect      bool `mapstructure:"reconnect"`       // Automatically reconnect if connection is lost
	ReconnectDelay int  `mapstructure:"reconnect_delay"` // Delay between reconnection attempts (seconds)
	MaxRetries     int  `mapstructure:"max_retries"`     // Maximum number of reconnection attempts (0 = infinite)

	// Logging settings
	LogLevel string `mapstructure:"log_level"` // Log level (debug, info, warn, error)
	LogFile  string `mapstructure:"log_file"`  // Path to log file
}

// LoadClientConfig loads the client configuration from a file
func LoadClientConfig(cfgFile string) (*ClientConfig, error) {
	// Default configuration
	defaults := map[string]interface{}{
		"server_addr":     "localhost:8080",
		"tun_device":      "tun0",
		"tun_ip":          "10.0.0.2/24",
		"mtu":             1400,
		"auth_mode":       "none",
		"reconnect":       true,
		"reconnect_delay": 5,
		"max_retries":     0,
		"log_level":       "info",
		"skip_verify":     false,
	}

	// Load configuration from file
	v, err := loadConfigFile(cfgFile, defaults, "client")
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}

	// Map to config struct
	var config ClientConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error parsing config: %v", err)
	}

	// Expand file paths
	if config.CACertFile, err = expandPath(config.CACertFile); err != nil {
		return nil, fmt.Errorf("invalid CA cert file path: %v", err)
	}
	if config.ClientCert, err = expandPath(config.ClientCert); err != nil {
		return nil, fmt.Errorf("invalid client cert file path: %v", err)
	}
	if config.ClientKey, err = expandPath(config.ClientKey); err != nil {
		return nil, fmt.Errorf("invalid client key file path: %v", err)
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
