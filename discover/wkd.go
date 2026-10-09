package discover

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/brodyhoskins/mailcloak/fetch"
)

// WKDHash returns the Web Key Directory hash of an address's local part:
// z-base-32(SHA-1(lowercase(local-part))).
func WKDHash(local string) string {
	sum := sha1.Sum([]byte(strings.ToLower(local)))
	return zbase32(sum[:])
}

// WKDURLs returns the advanced and direct method URLs for addr.
func WKDURLs(addr string) (advanced, direct string, err error) {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || domain == "" {
		return "", "", fmt.Errorf("wkd: invalid address %q", addr)
	}
	domain = strings.ToLower(domain)
	h, l := WKDHash(local), url.QueryEscape(local)
	advanced = fmt.Sprintf("https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s?l=%s", domain, domain, h, l)
	direct = fmt.Sprintf("https://%s/.well-known/openpgpkey/hu/%s?l=%s", domain, h, l)
	return advanced, direct, nil
}

// lookupWKD tries the advanced method, and the direct method only if the
// openpgpkey subdomain doesn't exist (as the spec says). With the DNSSEC
// dialer, "doesn't exist" is an NXDOMAIN that passed validation; a bogus
// answer is an error and never triggers the fallback.
func (r *Resolver) lookupWKD(ctx context.Context, addr string, prev *cachedKey) (*lookup, error) {
	advanced, direct, err := WKDURLs(addr)
	if err != nil {
		return nil, err
	}
	l, err := r.httpLookup(ctx, advanced, prev)
	var dnsErr *net.DNSError
	if err == nil || !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		return l, err
	}
	return r.httpLookup(ctx, direct, prev)
}

// lookupKeyserver queries a Verifying Keyserver (VKS) such as keys.openpgp.org.
func (r *Resolver) lookupKeyserver(ctx context.Context, addr string, prev *cachedKey) (*lookup, error) {
	return r.httpLookup(ctx, strings.TrimRight(r.Keyserver, "/")+"/vks/v1/by-email/"+url.PathEscape(addr), prev)
}

// httpLookup GETs u, revalidating prev if it came from the same URL.
func (r *Resolver) httpLookup(ctx context.Context, u string, prev *cachedKey) (*lookup, error) {
	var v fetch.Validators
	if prev != nil && prev.URL == u {
		v = prev.Validators
	}
	res, err := r.HTTP.Get(ctx, u, v)
	if err != nil {
		return nil, err
	}
	l := &lookup{URL: u, Validators: res.Validators, MaxAge: res.MaxAge, NoStore: res.NoStore}
	switch res.Status {
	case 200:
		l.Data = res.Body
	case 304:
		l.NotModified = true
	}
	return l, nil
}

const zbase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

func zbase32(b []byte) string {
	var out strings.Builder
	var buf uint32
	bits := 0
	for _, c := range b {
		buf = buf<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			out.WriteByte(zbase32Alphabet[(buf>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(zbase32Alphabet[(buf<<(5-bits))&31])
	}
	return out.String()
}
