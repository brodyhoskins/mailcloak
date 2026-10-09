// Package testdns is a tiny authoritative-looking DNS server for tests that
// stands in for a local validating resolver: each record is marked secure
// (AD bit set) or not, and names can be made bogus (SERVFAIL).
package testdns

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

type entry struct {
	rrs    []dns.RR
	secure bool
}

type Server struct {
	Addr string

	mu       sync.Mutex
	records  map[string]*entry // "name.|TYPE"
	names    map[string]bool   // names with any record (for NODATA vs NXDOMAIN)
	bogus    map[string]bool
	NXSecure bool // whether NXDOMAIN answers carry the AD bit
	Queries  int
}

// Start runs a server on a random loopback UDP port.
func Start(t testing.TB) *Server {
	s := &Server{records: map[string]*entry{}, names: map[string]bool{}, bogus: map[string]bool{}, NXSecure: true}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Addr = pc.LocalAddr().String()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve)}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return s
}

// Add adds a record in zone-file syntax, e.g. "example.org. 300 IN A 127.0.0.1".
func (s *Server) Add(t testing.TB, rr string, secure bool) {
	r, err := dns.NewRR(rr)
	if err != nil {
		t.Fatal(err)
	}
	s.AddRR(r, secure)
}

// AddRR adds a parsed record.
func (s *Server) AddRR(r dns.RR, secure bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := strings.ToLower(r.Header().Name)
	k := name + "|" + dns.TypeToString[r.Header().Rrtype]
	e := s.records[k]
	if e == nil {
		e = &entry{secure: secure}
		s.records[k] = e
	}
	e.rrs = append(e.rrs, r)
	s.names[name] = true
}

// Bogus makes every query for name fail validation.
func (s *Server) Bogus(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bogus[strings.ToLower(dns.Fqdn(name))] = true
}

func (s *Server) serve(w dns.ResponseWriter, req *dns.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Queries++
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	switch e := s.records[name+"|"+dns.TypeToString[q.Qtype]]; {
	case s.bogus[name]:
		m.Rcode = dns.RcodeServerFailure
	case e != nil:
		m.Answer = e.rrs
		m.AuthenticatedData = e.secure
	case s.names[name]:
		m.AuthenticatedData = true // NODATA
	default:
		m.Rcode = dns.RcodeNameError
		m.AuthenticatedData = s.NXSecure
	}
	w.WriteMsg(m)
}
