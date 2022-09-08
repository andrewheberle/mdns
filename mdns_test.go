package mdns

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func TestGenerateNSECResponse(t *testing.T) {
	type args struct {
		name  string
		ttl   uint32
		types []uint16
	}
	tests := []struct {
		name  string
		ttl   uint32
		types []uint16
		want  *dns.NSEC
	}{
		{
			"service-hostname.local.",
			120,
			nil,
			&dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   "service-hostname.local.",
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				NextDomain: "service-hostname.local.",
				TypeBitMap: nil,
			},
		},
		{
			"service-hostname.local.",
			120,
			[]uint16{dns.TypeA},
			&dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   "service-hostname.local.",
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				NextDomain: "service-hostname.local.",
				TypeBitMap: []uint16{dns.TypeA},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateNSECResponse(tt.name, tt.ttl, tt.types...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateNSECResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
