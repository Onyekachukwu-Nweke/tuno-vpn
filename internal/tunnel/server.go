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

// Tunneler represents a generic tunneling interface
type Tunneler interface {
	Start() error
	Stop() error
}

// ClientInfo holds information about a connected client
type ClientInfo struct {
	ID           string
	Conn         *cipher.TLSConn
	TunIP        net.IP
	LastActivity time.Time
	BytesIn      uint64
	BytesOut     uint64
}

// Server represents a Tuno VPN server
type Server struct {
	config       *config.ServerConfig
	listener     net.Listener
	tunDevice    *TUNDevice
	clients      map[string]*ClientInfo
	clientsMutex sync.RWMutex
	isRunning    bool
	stopCh       chan struct{}
	logger       *logrus.Logger
}

// NewServer creates a new Tuno VPN server
func NewServer(cfg *config.ServerConfig, logger *logrus.Logger) (*Server, error) {
	return &Server{
		config:    cfg,
		clients:   make(map[string]*ClientInfo),
		stopCh:    make(chan struct{}),
		logger:    logger,
		isRunning: false,
	}, nil
}

// Start starts the VPN server
func (s *Server) Start() error {
	if s.isRunning {
		return fmt.Errorf("server is already running")
	}

	var err error

	// Create TUN device
	s.tunDevice, err = NewTUNDevice(s.config, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Start the TUN device
	if err := s.tunDevice.Start(); err != nil {
		return fmt.Errorf("failed to start TUN device: %v", err)
	}

	// Create TCP listener
	s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		s.tunDevice.Stop()
		return fmt.Errorf("failed to listen on %s: %v", s.config.ListenAddr, err)
	}

	s.isRunning = true
	s.logger.Infof("Tuno VPN server started on %s", s.config.ListenAddr)

	// Start handling packets from TUN device
	go s.handleTUNPackets()

	// Accept client connections
	go s.acceptClients()

	// Wait for stop signal
	<-s.stopCh
	return nil
}

// Stop stops the VPN server
func (s *Server) Stop() error {
	if !s.isRunning {
		return nil
	}

	s.isRunning = false

	// Close the stop channel to signal all goroutines to stop
	close(s.stopCh)

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Disconnect all clients
	s.clientsMutex.Lock()
	for id, client := range s.clients {
		s.logger.Infof("Disconnecting client: %s", id)
		client.Conn.Close()
		delete(s.clients, id)
	}
	s.clientsMutex.Unlock()

	// Stop TUN device
	if s.tunDevice != nil {
		s.tunDevice.Stop()
	}

	s.logger.Info("Tuno VPN server stopped")
	return nil
}

// acceptClients accepts and handles client connections
func (s *Server) acceptClients() {
	for s.isRunning {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isRunning {
				s.logger.Errorf("Failed to accept client connection: %v", err)
			}
			continue
		}

		// Handle client in a new goroutine
		go s.handleClient(conn)
	}
}

// handleClient handles a client connection
func (s *Server) handleClient(conn net.Conn) {
	// Wrap connection with TLS
	tlsConn, err := cipher.NewTLSServerConn(conn, s.config, s.logger)
	if err != nil {
		s.logger.Errorf("Failed to establish TLS connection: %v", err)
		conn.Close()
		return
	}

	// Generate client ID based on the connection
	clientID := fmt.Sprintf("%s-%d", tlsConn.RemoteAddr().String(), time.Now().UnixNano())
	s.logger.Infof("New client connection: %s", clientID)

	// TODO: Implement client authentication here (for future milestones)

	// Assign client IP (TODO: implement proper IP assignment)
	clientIP := net.ParseIP("10.0.0.2") // For now, hardcoded

	// Create client info
	client := &ClientInfo{
		ID:           clientID,
		Conn:         tlsConn,
		TunIP:        clientIP,
		LastActivity: time.Now(),
	}

	// Add client to map
	s.clientsMutex.Lock()
	s.clients[clientID] = client
	s.clientsMutex.Unlock()

	// Handle packets from this client
	s.handleClientPackets(client)

	// Client disconnected, clean up
	s.clientsMutex.Lock()
	delete(s.clients, clientID)
	s.clientsMutex.Unlock()
	s.logger.Infof("Client disconnected: %s", clientID)
}

// handleClientPackets handles packets from a specific client
func (s *Server) handleClientPackets(client *ClientInfo) {
	buffer := make([]byte, MaxPacketSize)

	for s.isRunning {
		// Read packet from client
		n, err := client.Conn.Read(buffer)
		if err != nil {
			s.logger.Debugf("Client %s read error: %v", client.ID, err)
			break
		}

		// Update client activity time and bytes counter
		client.LastActivity = time.Now()
		client.BytesIn += uint64(n)

		// Process packet
		packet, err := ParsePacket(buffer[:n])
		if err != nil {
			s.logger.Debugf("Failed to parse packet from client %s: %v", client.ID, err)
			continue
		}

		// Decrement TTL to prevent routing loops
		if !packet.ModifyTTL() {
			s.logger.Debugf("Dropping packet from client %s due to expired TTL", client.ID)
			continue
		}

		// Write packet to TUN device
		_, err = s.tunDevice.Write(packet.Data)
		if err != nil {
			s.logger.Errorf("Failed to write packet to TUN device: %v", err)
			continue
		}
	}
}

// handleTUNPackets handles packets from the TUN device
func (s *Server) handleTUNPackets() {
	buffer := make([]byte, MaxPacketSize)

	for s.isRunning {
		// Read packet from TUN device
		n, err := s.tunDevice.Read(buffer)
		if err != nil {
			s.logger.Errorf("Failed to read from TUN device: %v", err)
			time.Sleep(time.Second) // Avoid tight loop on error
			continue
		}

		// Parse packet
		packet, err := ParsePacket(buffer[:n])
		if err != nil {
			s.logger.Debugf("Failed to parse packet from TUN: %v", err)
			continue
		}

		// Find client for this packet
		s.clientsMutex.RLock()
		var targetClient *ClientInfo
		for _, client := range s.clients {
			if packet.Destination.Equal(client.TunIP) {
				targetClient = client
				break
			}
		}
		s.clientsMutex.RUnlock()

		// If we found a client, send the packet
		if targetClient != nil {
			// Update bytes counter
			targetClient.BytesOut += uint64(len(packet.Data))

			// Write packet to client connection
			_, err = targetClient.Conn.Write(packet.Data)
			if err != nil {
				s.logger.Errorf("Failed to write packet to client %s: %v", targetClient.ID, err)
				continue
			}
		} else {
			// No client found for this packet, drop it
			s.logger.Debugf("No client found for packet destined to %s", packet.Destination)
		}
	}
}

// GetClientCount returns the number of connected clients
func (s *Server) GetClientCount() int {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()
	return len(s.clients)
}

// GetClients returns a copy of the client information
func (s *Server) GetClients() []ClientInfo {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	clients := make([]ClientInfo, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, *client)
	}
	return clients
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	return s.isRunning
}
