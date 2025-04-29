package cipher

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Onyekachukwu-Nweke/tuno-vpn/internal/config"
	"github.com/sirupsen/logrus"
)

// TLSConn wraps a TLS connection with additional functionality
type TLSConn struct {
	conn      *tls.Conn
	logger    *logrus.Logger
	closed    bool
	closeLock sync.Mutex
	writeLock sync.Mutex
	readLock  sync.Mutex
}

// NewTLSServerConn creates a new TLS server connection
func NewTLSServerConn(conn net.Conn, cfg *config.ServerConfig, logger *logrus.Logger) (*TLSConn, error) {
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %v", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Wrap the connection with TLS
	tlsConn := tls.Server(conn, tlsConfig)

	// Set a handshake deadline to prevent hanging
	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set TLS handshake deadline: %v", err)
	}

	// Perform the handshake
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Clear the deadline after handshake
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to clear deadline: %v", err)
	}

	logger.Debug("TLS server connection established")
	return &TLSConn{
		conn:   tlsConn,
		logger: logger,
	}, nil
}

// NewTLSClientConn creates a new TLS client connection
func NewTLSClientConn(conn net.Conn, cfg *config.ClientConfig, logger *logrus.Logger) (*TLSConn, error) {
	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: extractHostname(cfg.ServerAddr),
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Load CA certificate if provided
	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if using cert auth
	if cfg.AuthMode == "certificate" && cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Option to skip server certificate verification (not recommended)
	if cfg.SkipVerify {
		logger.Warn("TLS certificate verification disabled - this is insecure!")
		tlsConfig.InsecureSkipVerify = true
	}

	// Wrap the connection with TLS
	tlsConn := tls.Client(conn, tlsConfig)

	// Set a handshake deadline to prevent hanging
	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set TLS handshake deadline: %v", err)
	}

	// Perform the handshake
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Clear the deadline after handshake
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to clear deadline: %v", err)
	}

	logger.Debug("TLS client connection established")
	return &TLSConn{
		conn:   tlsConn,
		logger: logger,
	}, nil
}

// extractHostname extracts the hostname part from a host:port address
func extractHostname(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If there's an error, just return the original address
		return addr
	}
	return host
}

// Read reads data from the TLS connection
func (t *TLSConn) Read(b []byte) (int, error) {
	t.readLock.Lock()
	defer t.readLock.Unlock()

	if t.closed {
		return 0, io.ErrClosedPipe
	}

	return t.conn.Read(b)
}

// Write writes data to the TLS connection
func (t *TLSConn) Write(b []byte) (int, error) {
	t.writeLock.Lock()
	defer t.writeLock.Unlock()

	if t.closed {
		return 0, io.ErrClosedPipe
	}

	return t.conn.Write(b)
}

// Close closes the TLS connection
func (t *TLSConn) Close() error {
	t.closeLock.Lock()
	defer t.closeLock.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	t.logger.Debug("TLS connection closed")
	return t.conn.Close()
}

// SetReadDeadline sets the read deadline
func (t *TLSConn) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the write deadline
func (t *TLSConn) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// SetDeadline sets both read and write deadlines
func (t *TLSConn) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// LocalAddr returns the local network address
func (t *TLSConn) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (t *TLSConn) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// State returns the TLS connection state
func (t *TLSConn) State() tls.ConnectionState {
	return t.conn.ConnectionState()
}
