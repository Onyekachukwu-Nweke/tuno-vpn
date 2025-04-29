package tunnel

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Onyekachukwu-Nweke/tuno-vpn/internal/cipher"
	"github.com/Onyekachukwu-Nweke/tuno-vpn/internal/config"
	"github.com/sirupsen/logrus"
)

// Client represents a Tuno VPN client
type Client struct {
	config     *config.ClientConfig
	conn       *cipher.TLSConn
	tunDevice  *TUNDevice
	isRunning  bool
	stopCh     chan struct{}
	reconnect  bool
	retries    int
	mutex      sync.Mutex
	logger     *logrus.Logger
	bytesIn    uint64
	bytesOut   uint64
	lastActive time.Time
}

// NewClient creates a new Tuno VPN client
func NewClient(cfg *config.ClientConfig, logger *logrus.Logger) (*Client, error) {
	return &Client{
		config:     cfg,
		stopCh:     make(chan struct{}),
		logger:     logger,
		isRunning:  false,
		reconnect:  cfg.Reconnect,
		retries:    0,
		lastActive: time.Now(),
	}, nil
}

// Connect connects to the VPN server
func (c *Client) Connect() error {
	c.mutex.Lock()
	if c.isRunning {
		c.mutex.Unlock()
		return fmt.Errorf("client is already running")
	}
	c.isRunning = true
	c.mutex.Unlock()

	var err error

	// Create TUN device
	c.tunDevice, err = NewTUNDevice(c.config, c.logger)
	if err != nil {
		c.isRunning = false
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Start the TUN device
	if err := c.tunDevice.Start(); err != nil {
		c.isRunning = false
		return fmt.Errorf("failed to start TUN device: %v", err)
	}

	// Connect to server and run the main client loop
	go c.runMainLoop()

	// Wait for stop signal or reconnect
	<-c.stopCh
	return nil
}

// Stop stops the VPN client
func (c *Client) Stop() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.isRunning {
		return nil
	}

	c.isRunning = false
	close(c.stopCh)

	// Close TLS connection
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// Stop TUN device
	if c.tunDevice != nil {
		c.tunDevice.Stop()
	}

	c.logger.Info("Tuno VPN client stopped")
	return nil
}

// IsConnected returns whether the client is connected to the server
func (c *Client) IsConnected() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.isRunning && c.conn != nil
}

// runMainLoop is the main client loop that handles reconnection
func (c *Client) runMainLoop() {
	defer func() {
		// Signal that we're done
		select {
		case c.stopCh <- struct{}{}:
		default:
		}
	}()

	for c.isRunning {
		// Connect to server
		if err := c.connectToServer(); err != nil {
			c.logger.Errorf("Failed to connect to server: %v", err)

			// Check if we should retry
			if !c.reconnect || (c.config.MaxRetries > 0 && c.retries >= c.config.MaxRetries) {
				c.logger.Error("Maximum retry attempts reached, giving up")
				c.mutex.Lock()
				c.isRunning = false
				c.mutex.Unlock()
				return
			}

			c.retries++
			delay := time.Duration(c.config.ReconnectDelay) * time.Second
			c.logger.Infof("Retrying connection in %v (attempt %d/%d)...",
				delay, c.retries, c.config.MaxRetries)

			// Wait before reconnecting
			select {
			case <-time.After(delay):
				continue
			case <-c.stopCh:
				return
			}
		}

		// Reset retry counter on successful connection
		c.retries = 0

		// Start packet handling
		errCh := make(chan error, 2)
		go c.handleTUNPackets(errCh)
		go c.handleServerPackets(errCh)

		// Wait for an error or stop signal
		select {
		case err := <-errCh:
			c.logger.Errorf("Connection error: %v", err)
			if c.conn != nil {
				c.conn.Close()
				c.conn = nil
			}

			// If we're stopping, exit
			if !c.isRunning {
				return
			}

			// Otherwise try to reconnect after delay
			if c.reconnect {
				delay := time.Duration(c.config.ReconnectDelay) * time.Second
				c.logger.Infof("Reconnecting in %v...", delay)
				select {
				case <-time.After(delay):
					continue
				case <-c.stopCh:
					return
				}
			} else {
				c.mutex.Lock()
				c.isRunning = false
				c.mutex.Unlock()
				return
			}

		case <-c.stopCh:
			return
		}
	}
}

// connectToServer establishes a connection to the VPN server
func (c *Client) connectToServer() error {
	// Connect to server using TCP
	c.logger.Infof("Connecting to %s...", c.config.ServerAddr)
	tcpConn, err := net.DialTimeout("tcp", c.config.ServerAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}

	// Wrap connection with TLS
	c.conn, err = cipher.NewTLSClientConn(tcpConn, c.config, c.logger)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("failed to establish TLS connection: %v", err)
	}

	c.logger.Infof("Connected to %s", c.config.ServerAddr)
	c.lastActive = time.Now()

	// TODO: Add authentication handshake here for future milestones

	return nil
}

// handleTUNPackets handles packets from the TUN interface and sends them to the server
func (c *Client) handleTUNPackets(errCh chan<- error) {
	buffer := make([]byte, MaxPacketSize)

	for c.isRunning {
		// Read packet from TUN device
		n, err := c.tunDevice.Read(buffer)
		if err != nil {
			errCh <- fmt.Errorf("failed to read from TUN: %v", err)
			return
		}

		// Update statistics
		c.mutex.Lock()
		c.bytesOut += uint64(n)
		c.lastActive = time.Now()
		c.mutex.Unlock()

		// Parse packet
		packet, err := ParsePacket(buffer[:n])
		if err != nil {
			c.logger.Debugf("Failed to parse packet from TUN: %v", err)
			continue
		}

		// Send packet to server
		_, err = c.conn.Write(packet.Data)
		if err != nil {
			errCh <- fmt.Errorf("failed to write to server: %v", err)
			return
		}
	}
}

// handleServerPackets handles packets from the server and writes them to the TUN interface
func (c *Client) handleServerPackets(errCh chan<- error) {
	buffer := make([]byte, MaxPacketSize)

	for c.isRunning {
		// Read packet from server
		n, err := c.conn.Read(buffer)
		if err != nil {
			errCh <- fmt.Errorf("failed to read from server: %v", err)
			return
		}

		// Update statistics
		c.mutex.Lock()
		c.bytesIn += uint64(n)
		c.lastActive = time.Now()
		c.mutex.Unlock()

		// Parse packet
		packet, err := ParsePacket(buffer[:n])
		if err != nil {
			c.logger.Debugf("Failed to parse packet from server: %v", err)
			continue
		}

		// Write packet to TUN device
		_, err = c.tunDevice.Write(packet.Data)
		if err != nil {
			errCh <- fmt.Errorf("failed to write to TUN: %v", err)
			return
		}
	}
}

// GetStatistics returns the client connection statistics
func (c *Client) GetStatistics() (bytesIn, bytesOut uint64, lastActive time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.bytesIn, c.bytesOut, c.lastActive
}
