package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/brodyhoskins/mailcloak/dnssec"
	"github.com/brodyhoskins/mailcloak/fetch"
	"github.com/brodyhoskins/mailcloak/internal/testdns"
	"github.com/brodyhoskins/mailcloak/internal/testkeys"
)

func TestDANENameVector(t *testing.T) {
	// RFC 7929 section 3.
	got, _ := DANEName("hugh@example.com", "_openpgpkey")
	if want := "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com."; got != want {
		t.Fatalf("got %s", got)
	}
}

func TestOPENPGPKEYRequiresDNSSEC(t *testing.T) {
	srv := testdns.Start(t)
	add := func(addr string, secure bool) {
		name, _ := DANEName(addr, "_openpgpkey")
		key := testkeys.PublicBytes(t, testkeys.NewPGP(t, addr))
		srv.AddRR(&dns.OPENPGPKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeOPENPGPKEY, Class: dns.ClassINET, Ttl: 600},
			PublicKey: base64.StdEncoding.EncodeToString(key)}, secure)
	}
	add("signed@example.org", true)
	add("unsigned@example.org", false)
	bogus, _ := DANEName("bogus@example.org", "_openpgpkey")
	srv.Bogus(bogus)

	r := &Resolver{OPENPGPKEY: true, DNS: &dnssec.Resolver{Addr: srv.Addr}, Log: log}
	ctx := context.Background()
	if k, err := r.PGPKey(ctx, "signed@example.org"); err != nil || k == nil || k.Source != SourceOPENPGPKEY {
		t.Fatalf("signed record: %v, %v", k, err)
	}
	if k, err := r.PGPKey(ctx, "unsigned@example.org"); k != nil || err != nil {
		t.Fatalf("unsigned record must be ignored: %v, %v", k, err)
	}
	if k, err := r.PGPKey(ctx, "bogus@example.org"); k != nil || err == nil {
		t.Fatalf("bogus record must be a lookup error: %v, %v", k, err)
	}
}

func TestSMIMEA(t *testing.T) {
	dir := t.TempDir()
	testkeys.SMIME(t, dir, "carol@example.org", false)
	b, _ := os.ReadFile(filepath.Join(dir, "carol@example.org.crt"))
	blk, _ := pem.Decode(b)
	cert, _ := x509.ParseCertificate(blk.Bytes)

	srv := testdns.Start(t)
	add := func(addr string, usage uint8) {
		name, _ := DANEName(addr, "_smimecert")
		srv.AddRR(&dns.SMIMEA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSMIMEA, Class: dns.ClassINET, Ttl: 600},
			Usage: usage, Selector: 0, MatchingType: 0, Certificate: hex.EncodeToString(cert.Raw)}, true)
	}
	add("carol@example.org", 3) // DANE-EE: trusted as published
	add("pkix@example.org", 1)  // PKIX-EE: must also chain to the roots

	r := &Resolver{SMIMEA: true, DNS: &dnssec.Resolver{Addr: srv.Addr}, SMIMERoots: x509.NewCertPool(), Log: log}
	ctx := context.Background()
	if c, err := r.SMIMECert(ctx, "carol@example.org"); err != nil || c == nil || c.Source != SourceSMIMEA {
		t.Fatalf("DANE-EE: %v, %v", c, err)
	}
	if c, _ := r.SMIMECert(ctx, "pkix@example.org"); c != nil {
		t.Fatal("PKIX-EE accepted without a trusted chain")
	}
	r.SMIMERoots.AddCert(cert)
	if c, _ := r.SMIMECert(ctx, "pkix@example.org"); c == nil {
		t.Fatal("PKIX-EE with a trusted chain rejected")
	}
}

// TestWKDFallbackThroughDNSSEC: the direct method is only tried when the
// openpgpkey subdomain authentically doesn't exist, never on a bogus answer.
func TestWKDFallbackThroughDNSSEC(t *testing.T) {
	ks := newKeyServer(t)
	for _, addr := range []string{"a@nx.example", "b@bogus.example"} {
		local, domain, _ := strings.Cut(addr, "@")
		ks.keys["/.well-known/openpgpkey/hu/"+WKDHash(local)] = testkeys.PublicBytes(t, testkeys.NewPGP(t, local+"@"+domain))
	}

	srv := testdns.Start(t)
	srv.Add(t, "nx.example. 300 IN A 127.0.0.1", true)
	srv.Add(t, "bogus.example. 300 IN A 127.0.0.1", true)
	srv.Bogus("openpgpkey.bogus.example")
	resolver := &dnssec.Resolver{Addr: srv.Addr}

	// Resolve through the DNSSEC resolver, then connect to the test server's
	// port instead of 443.
	_, port, _ := net.SplitHostPort(ks.ts.Listener.Addr().String())
	tr := fetch.NewTransport(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		return resolver.DialContext(ctx, network, net.JoinHostPort(host, port))
	})
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	r := &Resolver{WKD: true, HTTP: &fetch.Client{HTTP: &http.Client{Transport: tr}, MaxBody: maxKeyBytes}, Log: log}
	ctx := context.Background()

	if k, err := r.PGPKey(ctx, "a@nx.example"); err != nil || k == nil {
		t.Fatalf("authenticated NXDOMAIN should fall back to the direct method: %v, %v", k, err)
	}
	if k, err := r.PGPKey(ctx, "b@bogus.example"); k != nil || err == nil {
		t.Fatalf("bogus answer must not fall back: %v, %v", k, err)
	}
}
