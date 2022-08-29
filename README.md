# mdns

This package is used to Query and RR classes for DNS requests/responses to conform to mDNS.

## Usage

This package is designed to be used with `github.com/miekg/dns`:

```go
package main

import "github.com/miekg/dns"

func handle(w dns.ResponseWriter, r *dns.Msg) {
    m := new(dns.Msg)
	m.SetReply(r)

    if r.Question[0].Qtype == dns.TypePTR {
        m.Answer = append(m.Answer, &dns.PTR{
            Hdr: dns.RR_Header{Name: "_googlecast._tcp.local.", Rrtype: dns.TypePTR, Class: mdns.RRClass(dns.ClassINET, true), Ttl: 120},
            Ptr: "Chromecast-deadbeef-5c74-0091-b8b0-bc27e95d8e84._googlecast._tcp.local.",
        })
    }
    
    w.WriteMsg(m)
}
```