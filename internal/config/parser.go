package config

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// defaultConfigDir returns the default configuration directory
func defaultConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "/etc/tuno"
	}
	return filepath.Join(homeDir, ".tuno")
}

// loadConfigFile loads configuration from the specified file or default locations
func loadConfigFile(cfgFile string, defaults map[string]interface{}, configType string) (*viper.Viper, error) {
	v := viper.New()

	// Set defaults
	for key, value := range defaults {
		v.SetDefault(key, value)
	}

	// If config file is specified, use it
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Look for config in default locations
		v.SetConfigName(configType) // config file name without extension
		v.SetConfigType("yaml")     // config file format

		// Add search paths
		configDir := defaultConfigDir()
		v.AddConfigPath(".")         // Current directory
		v.AddConfigPath(configDir)   // User config directory (~/.tuno)
		v.AddConfigPath("/etc/tuno") // System config directory
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		// Config file not found is not a fatal error if we have defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	return v, nil
}

// validateConfig validates the common configuration parameters
func validateConfig(config interface{}) error {
	switch cfg := config.(type) {
	case *ServerConfig:
		if cfg.ListenAddr == "" {
			return errors.New("listen address cannot be empty")
		}
		if cfg.TunDevice == "" {
			return errors.New("TUN device name cannot be empty")
		}
		if cfg.TunIP == "" {
			return errors.New("TUN IP address cannot be empty")
		}
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return errors.New("TLS certificate and key files are required")
		}
	case *ClientConfig:
		if cfg.ServerAddr == "" {
			return errors.New("server address cannot be empty")
		}
		if cfg.TunDevice == "" {
			return errors.New("TUN device name cannot be empty")
		}
		if cfg.TunIP == "" {
			return errors.New("TUN IP address cannot be empty")
		}
	default:
		return errors.New("unknown config type")
	}
	return nil
}

// expandPaths expands file paths that may be relative or use ~ for home directory
func expandPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	// Expand ~ to home directory
	if path[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(homeDir, path[1:])
	}

	// Make absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	return absPath, nil
}
