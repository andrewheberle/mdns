package mdns

import "net"

const (
	QueryClassCacheFlush uint16 = 1 << 15
)

var (
	// Multicast groups used by mDNS
	GroupIPv4 = net.IPv4(224, 0, 0, 251)
	GroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	WildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: 5353,
	}
	WildcardAddrIPv6 = &net.UDPAddr{
		IP: net.ParseIP("ff02::"),
		// IP:   net.ParseIP("fd00::12d3:26e7:48db:e7d"),
		Port: 5353,
	}

	// mDNS endpoint addresses
	GroupIpv4Addr = &net.UDPAddr{
		IP:   GroupIPv4,
		Port: 5353,
	}
	GroupIpv6Addr = &net.UDPAddr{
		IP:   GroupIPv6,
		Port: 5353,
	}
)

// PackClass packs a query or RR class setting either the unicast-response or cache-flush
// bit respectively
func PackClass(class uint16, flag bool) uint16 {
	if flag {
		return class | 1<<15
	}

	return class ^ 1<<15
}

// UnpackClass unpacks a query or RR class returning the original class and if the
// unicast-response or cache-flush bit was set respectively
func UnpackClass(class uint16) (uint16, bool) {
	return class ^ 1<<15, (class & 1 << 15) != 0
}
