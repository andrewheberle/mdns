package mdns

import (
	"net"

	"github.com/miekg/dns"
)

const (
	CacheFlush uint16 = 1 << 15
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
		return class | CacheFlush
	}

	return class ^ CacheFlush
}

// UnpackClass unpacks a query or RR class returning the original class and if the
// unicast-response or cache-flush bit was set respectively
func UnpackClass(class uint16) (uint16, bool) {
	return class ^ CacheFlush, (class & CacheFlush) != 0
}

// From RFC6762
// 18.12.  Repurposing of Top Bit of qclass in Question Section
//
//	In the Question Section of a Multicast DNS query, the top bit of the
//	qclass field is used to indicate that unicast responses are preferred
//	for this particular question.  (See Section 5.4.)
func IsUnicastQuestion(q dns.Question) bool {

	return q.Qclass&CacheFlush != 0
}
