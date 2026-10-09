// Package dnssec sends DNS queries to a validating resolver and reports
// whether answers were authenticated. Validation itself is the resolver's job
// (Unbound, systemd-resolved, ...); mailcloak trusts the AD bit only from a
// resolver on loopback or in an explicitly trusted network, where it can't
// be forged in transit. This is the same model as Postfix's DANE support.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ErrBogus is returned when the resolver answers SERVFAIL, which a
// validating resolver does for answers that fail DNSSEC validation.
var ErrBogus = errors.New("dnssec: SERVFAIL (validation failed or resolver unreachable upstream)")

// ErrUntrusted is returned when the resolver in use isn't on loopback or in
// a trusted network, so its AD bit can't be relied on.
var ErrUntrusted = errors.New("dnssec: resolver is not trusted")

// Resolver queries one validating resolver: Addr if set, otherwise the first
// nameserver in ResolvConf, re-read whenever the file changes so a
// long-running process follows the system's current resolver.
type Resolver struct {
	Addr       string // host:port; empty means use ResolvConf
	ResolvConf string // default /etc/resolv.conf
	Trusted    []netip.Prefix
	Timeout    time.Duration

	mu      sync.Mutex
	rcStamp time.Time
	rcSize  int64
	rcAddr  string
}

// Current returns the resolver address to use now, or an error if it isn't
// trusted.
func (r *Resolver) Current() (string, error) {
	addr := r.Addr
	if addr == "" {
		var err error
		if addr, err = r.fromResolvConf(); err != nil {
			return "", err
		}
	}
	if !Trusted(addr, r.Trusted) {
		return "", fmt.Errorf("%w: %s is neither loopback nor in dns.trusted_networks", ErrUntrusted, addr)
	}
	return addr, nil
}

// Trusted reports whether addr (host:port) is on loopback or in nets.
func Trusted(addr string, nets []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Resolver) fromResolvConf() (string, error) {
	path := r.ResolvConf
	if path == "" {
		path = "/etc/resolv.conf"
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("dnssec: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rcAddr != "" && fi.ModTime().Equal(r.rcStamp) && fi.Size() == r.rcSize {
		return r.rcAddr, nil
	}
	cc, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return "", fmt.Errorf("dnssec: %w", err)
	}
	if len(cc.Servers) == 0 {
		return "", fmt.Errorf("dnssec: no nameserver in %s", path)
	}
	r.rcStamp, r.rcSize = fi.ModTime(), fi.Size()
	r.rcAddr = net.JoinHostPort(cc.Servers[0], cc.Port)
	return r.rcAddr, nil
}

// Answer is the result of a query.
type Answer struct {
	RRs      []dns.RR      // answer RRs of the queried type
	Secure   bool          // the resolver validated the answer (AD bit)
	NXDomain bool          // the name does not exist
	TTL      time.Duration // smallest TTL among RRs
}

// Query looks up name/qtype with the DO and AD bits set.
func (r *Resolver) Query(ctx context.Context, name string, qtype uint16) (*Answer, error) {
	addr, err := r.Current()
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.AuthenticatedData = true
	m.RecursionDesired = true

	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	c := &dns.Client{Net: "udp", Timeout: timeout}
	resp, _, err := c.ExchangeContext(ctx, m, addr)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dnssec: query %s: %w", name, err)
	}

	a := &Answer{Secure: resp.AuthenticatedData}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		a.NXDomain = true
		return a, nil
	case dns.RcodeServerFailure:
		return nil, ErrBogus
	default:
		return nil, fmt.Errorf("dnssec: query %s: %s", name, dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != qtype {
			continue // e.g. the CNAMEs leading to the answer
		}
		ttl := time.Duration(rr.Header().Ttl) * time.Second
		if len(a.RRs) == 0 || ttl < a.TTL {
			a.TTL = ttl
		}
		a.RRs = append(a.RRs, rr)
	}
	return a, nil
}

// DialContext resolves the host in addr through the resolver and connects.
// Answers that fail validation are errors. Unsigned zones are allowed: the
// connections this is used for are TLS, which authenticates the server.
// A name that doesn't exist yields a *net.DNSError with IsNotFound set.
func (r *Resolver) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return (&net.Dialer{}).DialContext(ctx, network, netip.AddrPortFrom(ip, 0).Addr().String()+":"+port)
	}

	var ips []string
	var lastErr error
	nx := 0
	for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeA} {
		a, err := r.Query(ctx, host, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		if a.NXDomain {
			nx++
			continue
		}
		for _, rr := range a.RRs {
			switch v := rr.(type) {
			case *dns.AAAA:
				ips = append(ips, v.AAAA.String())
			case *dns.A:
				ips = append(ips, v.A.String())
			}
		}
	}
	if len(ips) == 0 {
		if nx == 2 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, &net.DNSError{Err: "no addresses", Name: host}
	}
	d := &net.Dialer{}
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
