package dnssec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/brodyhoskins/mailcloak/internal/testdns"
)

func TestQueryReportsValidation(t *testing.T) {
	srv := testdns.Start(t)
	srv.Add(t, "signed.example. 300 IN A 192.0.2.1", true)
	srv.Add(t, "unsigned.example. 600 IN A 192.0.2.2", false)
	srv.Bogus("bogus.example")
	r := &Resolver{Addr: srv.Addr}
	ctx := context.Background()

	a, err := r.Query(ctx, "signed.example", dns.TypeA)
	if err != nil || !a.Secure || len(a.RRs) != 1 || a.TTL.Seconds() != 300 {
		t.Fatalf("signed: %+v, %v", a, err)
	}
	if a, _ := r.Query(ctx, "unsigned.example", dns.TypeA); a.Secure {
		t.Error("unsigned answer reported secure")
	}
	if _, err := r.Query(ctx, "bogus.example", dns.TypeA); !errors.Is(err, ErrBogus) {
		t.Errorf("bogus: want ErrBogus, got %v", err)
	}
	if a, err := r.Query(ctx, "missing.example", dns.TypeA); err != nil || !a.NXDomain {
		t.Errorf("missing: want NXDOMAIN, got %+v, %v", a, err)
	}
}

func TestDialContext(t *testing.T) {
	srv := testdns.Start(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	srv.Add(t, "host.example. 300 IN A 127.0.0.1", false) // unsigned is fine: TLS authenticates
	srv.Bogus("bogus.example")
	r := &Resolver{Addr: srv.Addr}
	ctx := context.Background()

	c, err := r.DialContext(ctx, "tcp", net.JoinHostPort("host.example", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()

	if _, err := r.DialContext(ctx, "tcp", "bogus.example:"+port); !errors.Is(err, ErrBogus) {
		t.Errorf("bogus name must not be dialled: %v", err)
	}
	_, err = r.DialContext(ctx, "tcp", "missing.example:"+port)
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Errorf("missing name: want not-found DNSError, got %v", err)
	}
}

func TestTrusted(t *testing.T) {
	nets := []netip.Prefix{netip.MustParsePrefix("100.100.100.100/32"), netip.MustParsePrefix("fd7a:115c:a1e0::53/128")}
	for addr, want := range map[string]bool{
		"127.0.0.1:53": true, "[::1]:53": true, "127.0.0.53:53": true, // loopback, always
		"100.100.100.100:53": true, "[fd7a:115c:a1e0::53]:53": true, // listed
		"100.64.0.1:53": false, "192.168.1.1:53": false, "9.9.9.9:53": false,
	} {
		if got := Trusted(addr, nets); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
}

// TestFollowsResolvConf: a long-running process picks up resolver changes,
// and refuses to use the resolver while the current one isn't trusted.
func TestFollowsResolvConf(t *testing.T) {
	rc := filepath.Join(t.TempDir(), "resolv.conf")
	write := func(ns string, at time.Time) {
		os.WriteFile(rc, []byte("nameserver "+ns+"\n"), 0o644)
		os.Chtimes(rc, at, at) // distinct mtimes, even within one clock tick
	}
	r := &Resolver{ResolvConf: rc, Trusted: []netip.Prefix{netip.MustParsePrefix("100.100.100.100/32")}}
	now := time.Now()

	write("100.100.100.100", now) // on Tailscale
	if addr, err := r.Current(); err != nil || addr != "100.100.100.100:53" {
		t.Fatalf("trusted network: %q, %v", addr, err)
	}
	write("192.0.2.53", now.Add(time.Second)) // Tailscale down: e.g. a café's resolver
	if _, err := r.Current(); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted resolver accepted: %v", err)
	}
	if _, err := r.Query(context.Background(), "example.org", dns.TypeA); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("query sent to untrusted resolver: %v", err)
	}
	write("127.0.0.1", now.Add(2*time.Second)) // local Unbound
	if addr, err := r.Current(); err != nil || addr != "127.0.0.1:53" {
		t.Fatalf("loopback: %q, %v", addr, err)
	}
}
