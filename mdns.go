package mdns

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
