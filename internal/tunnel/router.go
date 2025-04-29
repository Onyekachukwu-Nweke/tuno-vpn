package tunnel

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

// RouteType indicates how a packet should be routed
type RouteType int

const (
	// RouteTypeTUN routes the packet via the TUN interface
	RouteTypeTUN RouteType = iota
	// RouteTypeInternet routes the packet via the internet
	RouteTypeInternet
	// RouteTypeDrop drops the packet
	RouteTypeDrop
)

// Route represents a network route
type Route struct {
	// Network CIDR (e.g., 192.168.1.0/24)
	Network *net.IPNet
	// Type of routing to apply
	Type RouteType
}

// Router handles packet routing decisions
type Router struct {
	routes    []Route
	mutex     sync.RWMutex
	logger    *logrus.Logger
	ipv4Count int
	ipv6Count int
}

// NewRouter creates a new router with default routes
func NewRouter(logger *logrus.Logger) *Router {
	r := &Router{
		routes: make([]Route, 0),
		logger: logger,
	}

	// Add default routes for private networks
	r.addPrivateNetworkRoutes()

	return r
}

// addPrivateNetworkRoutes adds routes for standard private networks
func (r *Router) addPrivateNetworkRoutes() {
	// RFC1918 private networks
	r.AddRoute("10.0.0.0/8", RouteTypeTUN)     // Class A private network
	r.AddRoute("172.16.0.0/12", RouteTypeTUN)  // Class B private network
	r.AddRoute("192.168.0.0/16", RouteTypeTUN) // Class C private network

	// Link-local addresses
	r.AddRoute("169.254.0.0/16", RouteTypeTUN) // IPv4 link-local
	r.AddRoute("fe80::/10", RouteTypeTUN)      // IPv6 link-local

	// Default route - send everything else directly
	r.AddRoute("0.0.0.0/0", RouteTypeInternet) // IPv4 default
	r.AddRoute("::/0", RouteTypeInternet)      // IPv6 default
}

// AddRoute adds a new route to the routing table
func (r *Router) AddRoute(cidr string, routeType RouteType) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if we already have this route
	for i, route := range r.routes {
		if route.Network.String() == network.String() {
			// Replace existing route
			r.routes[i].Type = routeType
			r.logger.Infof("Updated route %s to %v", cidr, routeType)
			return nil
		}
	}

	// Add new route
	r.routes = append(r.routes, Route{
		Network: network,
		Type:    routeType,
	})

	// Update metrics
	if network.IP.To4() != nil {
		r.ipv4Count++
	} else {
		r.ipv6Count++
	}

	r.logger.Infof("Added route %s as %v", cidr, routeType)
	return nil
}

// RemoveRoute removes a route from the routing table
func (r *Router) RemoveRoute(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, route := range r.routes {
		if route.Network.String() == network.String() {
			// Remove route by swapping with last element and truncating
			r.routes[i] = r.routes[len(r.routes)-1]
			r.routes = r.routes[:len(r.routes)-1]

			// Update metrics
			if network.IP.To4() != nil {
				r.ipv4Count--
			} else {
				r.ipv6Count--
			}

			r.logger.Infof("Removed route %s", cidr)
			return nil
		}
	}

	return fmt.Errorf("route not found: %s", cidr)
}

// GetRoute determines how a packet should be routed
func (r *Router) GetRoute(ip net.IP) RouteType {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Find the most specific route that matches the IP
	var matchedRoute *Route
	var matchedMaskSize int

	for i := range r.routes {
		route := &r.routes[i]
		if route.Network.Contains(ip) {
			// Get the mask size
			maskSize, _ := route.Network.Mask.Size()

			// If this is the first match or has a more specific mask
			if matchedRoute == nil || maskSize > matchedMaskSize {
				matchedRoute = route
				matchedMaskSize = maskSize
			}
		}
	}

	if matchedRoute != nil {
		return matchedRoute.Type
	}

	// Default to internet routing if no match is found
	return RouteTypeInternet
}

// GetRoutes returns a copy of all routes
func (r *Router) GetRoutes() []Route {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Create a copy to avoid race conditions
	routes := make([]Route, len(r.routes))
	copy(routes, r.routes)

	return routes
}

// GetStats returns statistics about the routing table
func (r *Router) GetStats() (int, int, int) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return len(r.routes), r.ipv4Count, r.ipv6Count
}

// ClearRoutes removes all routes
func (r *Router) ClearRoutes() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.routes = make([]Route, 0)
	r.ipv4Count = 0
	r.ipv6Count = 0

	r.logger.Info("All routes cleared")
}

// ShouldRoute determines if a packet should be routed over the VPN or direct
func (r *Router) ShouldRoute(packet *Packet) RouteType {
	return r.GetRoute(packet.Destination)
}
