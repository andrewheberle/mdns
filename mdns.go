package mdns

func setclass(class uint16, upperbit bool) uint16 {
	if upperbit {
		return class | 1<<15
	}

	return class ^ 1<<15
}

// QueryClass returns a query class with the unicast-response bit set as requested
func QueryClass(class uint16, unicastResponse bool) uint16 {
	return setclass(class, unicastResponse)
}

// RRClass returns a query class with the cache-flush bit set as requested
func RRClass(class uint16, cacheFlush bool) uint16 {
	return setclass(class, cacheFlush)
}
