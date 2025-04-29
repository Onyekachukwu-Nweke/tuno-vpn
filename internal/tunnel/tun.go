package tunnel

import (
	"fmt"
	"github.com/Onyekachukwu-Nweke/tuno-vpn/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"net"
	"strings"
	"unsafe"
)

// TUNDevice represents a virtual TUN network interface
type TUNDevice struct {
	name      string
	fd        int
	mtu       int
	cidr      string
	ipNet     *net.IPNet
	stack     *stack.Stack
	logger    *logrus.Logger
	isRunning bool
}

// NewTUNDevice creates a new TUN device
func NewTUNDevice(cfg interface{}, logger *logrus.Logger) (*TUNDevice, error) {
	var tunDevice string
	var tunIP string
	var mtu int

	// Extract configuration based on type
	switch c := cfg.(type) {
	case *config.ServerConfig:
		tunDevice = c.TunDevice
		tunIP = c.TunIP
		mtu = c.MTU
	case *config.ClientConfig:
		tunDevice = c.TunDevice
		tunIP = c.TunIP
		mtu = c.MTU
	default:
		return nil, fmt.Errorf("unsupported config type")
	}

	// Parse IP network
	ip, ipNet, err := net.ParseCIDR(tunIP)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN IP address: %v", err)
	}

	// Create the TUN device
	fd, err := createTUN(tunDevice, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Configure the IP address
	if err := configureTUN(tunDevice, ip, ipNet, mtu); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to configure TUN device: %v", err)
	}

	// Create a new network stack
	s := createNetworkStack()

	return &TUNDevice{
		name:   tunDevice,
		fd:     fd,
		mtu:    mtu,
		cidr:   tunIP,
		ipNet:  ipNet,
		stack:  s,
		logger: logger,
	}, nil
}

func createTUN(name string, mtu int) (int, error) {
	// Open the TUN device file
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Prepare the ifr structure for TUNSETIFF
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	// IFF_TUN | IFF_NO_PI
	ifr[unix.IFNAMSIZ] = 0x01
	ifr[unix.IFNAMSIZ+1] = 0x10

	// Setup the TUN device
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("failed to set TUN device parameters: %v", errno)
	}

	return fd, nil
}

// configureTUN configures the TUN device with IP address and MTU
func configureTUN(name string, ip net.IP, ipNet *net.IPNet, mtu int) error {
	// Get the link for the device
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link for %s: %v", name, err)
	}

	// Set the MTU
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Create the IP address to add to the interface
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}

	// Add the address to the interface
	if err := netlink.AddrAdd(link, addr); err != nil {
		// Ignore if the address already exists
		if !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("failed to add IP address: %v", err)
		}
	}

	// Bring the interface up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

// createNetworkStack creates a new gVisor network stack
func createNetworkStack() *stack.Stack {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	return s
}

// Start starts reading from the TUN device
func (t *TUNDevice) Start() error {
	t.isRunning = true
	t.logger.Infof("TUN device %s started with IP %s", t.name, t.cidr)
	return nil
}

// Stop stops the TUN device and closes the file descriptor
func (t *TUNDevice) Stop() error {
	if !t.isRunning {
		return nil
	}

	t.isRunning = false
	err := unix.Close(t.fd)
	t.logger.Infof("TUN device %s stopped", t.name)
	return err
}

// Read reads a packet from the TUN device
func (t *TUNDevice) Read(buf []byte) (int, error) {
	return unix.Read(t.fd, buf)
}

// Write writes a packet to the TUN device
func (t *TUNDevice) Write(buf []byte) (int, error) {
	return unix.Write(t.fd, buf)
}
