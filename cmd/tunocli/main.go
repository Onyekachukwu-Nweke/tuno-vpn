package main

import (
	"fmt"
	"github.com/Onyekachukwu-Nweke/tuno-vpn/internal/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var (
	cfgFile    string
	verbosity  int
	serverMode bool
	clientMode bool
	serverAddr string
	listenAddr string
	tunDevice  string
	tunIP      string
	certFile   string
	keyFile    string
	caCertFile string
)

var rootCmd = &cobra.Command{
	Use:   "tuno",
	Short: "Tuno VPN - A secure, modular VPN system written in Go",
	Long: `Tuno VPN is a modular VPN system built in Go with strong encryption,
process safety features, split tunneling capabilities, and optional
peer-to-peer support for decentralized connections.`,
	Run: func(cmd *cobra.Command, args []string) {
		// If no subcommand is specified, show help
		cmd.Help()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Tuno VPN v0.1.0")
	},
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run in server mode",
	Run: func(cmd *cobra.Command, args []string) {
		log := setupLogging()
		cfg, err := config.LoadServerConfig(cfgFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		// Apply command-line overrides
		if listenAddr != "" {
			cfg.ListenAddr = listenAddr
		}
		if tunDevice != "" {
			cfg.TunDevice = tunDevice
		}
		if tunIP != "" {
			cfg.TunIP = tunIP
		}
		if certFile != "" {
			cfg.CertFile = certFile
		}
		if keyFile != "" {
			cfg.KeyFile = keyFile
		}

		log.Infof("Starting Tuno VPN server on %s", cfg.ListenAddr)
		srv, err := tunnel.NewServer(cfg, log)
		if err != nil {
			log.Fatalf("Failed to create server: %v", err)
		}

		handleSignals(srv, log)
		if err := srv.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	},
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run in client mode",
	Run: func(cmd *cobra.Command, args []string) {
		log := setupLogging()
		cfg, err := config.LoadClientConfig(cfgFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		// Apply command-line overrides
		if serverAddr != "" {
			cfg.ServerAddr = serverAddr
		}
		if tunDevice != "" {
			cfg.TunDevice = tunDevice
		}
		if tunIP != "" {
			cfg.TunIP = tunIP
		}
		if caCertFile != "" {
			cfg.CACertFile = caCertFile
		}

		log.Infof("Connecting to Tuno VPN server at %s", cfg.ServerAddr)
		client, err := tunnel.NewClient(cfg, log)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}

		handleSignals(client, log)
		if err := client.Connect(); err != nil {
			log.Fatalf("Client error: %v", err)
		}
	},
}

func setupLogging() *logrus.Logger {
	log := logger.New()

	// Set log level based on verbosity flag
	switch verbosity {
	case 0:
		log.SetLevel(logrus.InfoLevel)
	case 1:
		log.SetLevel(logrus.DebugLevel)
	default:
		log.SetLevel(logrus.TraceLevel)
	}

	return log
}

func handleSignals(t tunnel.Tunneler, log *logrus.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Infof("Received signal %s, shutting down", sig)
		t.Stop()
		os.Exit(0)
	}()
}

func init() {
	// Root command flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbose", "v", 0, "verbosity level (0-2)")

	// Server command flags
	serverCmd.Flags().StringVar(&listenAddr, "listen", "", "address to listen on (e.g., 0.0.0.0:8080)")
	serverCmd.Flags().StringVar(&tunDevice, "tun", "", "TUN device name (e.g., tun0)")
	serverCmd.Flags().StringVar(&tunIP, "tun-ip", "", "TUN interface IP (e.g., 10.0.0.1/24)")
	serverCmd.Flags().StringVar(&certFile, "cert", "", "TLS certificate file")
	serverCmd.Flags().StringVar(&keyFile, "key", "", "TLS key file")

	// Client command flags
	clientCmd.Flags().StringVar(&serverAddr, "server", "", "server address (e.g., example.com:8080)")
	clientCmd.Flags().StringVar(&tunDevice, "tun", "", "TUN device name (e.g., tun0)")
	clientCmd.Flags().StringVar(&tunIP, "tun-ip", "", "TUN interface IP (e.g., 10.0.0.2/24)")
	clientCmd.Flags().StringVar(&caCertFile, "ca-cert", "", "CA certificate file for server verification")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(clientCmd)
}

func main() {
	// Create default config directory if it doesn't exist
	configDir := filepath.Join(os.Getenv("HOME"), ".tuno")
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
