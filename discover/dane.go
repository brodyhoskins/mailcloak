package discover

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/brodyhoskins/mailcloak/smime"
)

// DANEName returns the owner name for an address's OPENPGPKEY (RFC 7929,
// label "_openpgpkey") or SMIMEA (RFC 8162, label "_smimecert") record:
// hex(SHA-256(local-part)[:28]).<label>.<domain>.
func DANEName(addr, label string) (string, error) {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || domain == "" {
		return "", fmt.Errorf("dane: invalid address %q", addr)
	}
	sum := sha256.Sum256([]byte(local))
	return hex.EncodeToString(sum[:28]) + "." + label + "." + strings.ToLower(domain) + ".", nil
}

// daneQuery looks up the record for addr. RFC 7929 hashes the local part
// as written; if that has no answer and it has upper-case letters, the
// lower-cased form is tried too. Only DNSSEC-authenticated answers count:
// an unsigned zone is treated as publishing nothing.
func (r *Resolver) daneQuery(ctx context.Context, addr, label string, qtype uint16) ([]dns.RR, *lookup, error) {
	local, domain, _ := strings.Cut(addr, "@")
	candidates := []string{local}
	if lower := strings.ToLower(local); lower != local {
		candidates = append(candidates, lower)
	}
	l := &lookup{MaxAge: -1}
	for _, lp := range candidates {
		name, err := DANEName(lp+"@"+domain, label)
		if err != nil {
			return nil, nil, err
		}
		a, err := r.DNS.Query(ctx, name, qtype)
		if err != nil {
			return nil, nil, err
		}
		if !a.Secure {
			if len(a.RRs) > 0 {
				r.Log.Info("discover: ignoring unauthenticated DNS record", "name", name)
			}
			continue
		}
		if len(a.RRs) > 0 {
			l.MaxAge = a.TTL
			return a.RRs, l, nil
		}
	}
	return nil, l, nil
}

// lookupOPENPGPKEY fetches an OPENPGPKEY record.
func (r *Resolver) lookupOPENPGPKEY(ctx context.Context, addr string, _ *cachedKey) (*lookup, error) {
	rrs, l, err := r.daneQuery(ctx, addr, "_openpgpkey", dns.TypeOPENPGPKEY)
	if err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		b, err := base64.StdEncoding.DecodeString(rr.(*dns.OPENPGPKEY).PublicKey)
		if err == nil && selectKey(b, addr) != nil {
			l.Data = b
			break
		}
	}
	return l, nil
}

// lookupSMIMEA fetches an SMIMEA record carrying a full end-entity
// certificate (selector 0, matching type 0). Usage 3 (DANE-EE) is trusted
// as published; usage 1 (PKIX-EE) must also chain to the S/MIME roots.
// Trust-anchor usages (0, 2) and hashed forms don't give us a certificate
// to encrypt to and are skipped.
func (r *Resolver) lookupSMIMEA(ctx context.Context, addr string, _ *cachedKey) (*lookup, error) {
	rrs, l, err := r.daneQuery(ctx, addr, "_smimecert", dns.TypeSMIMEA)
	if err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		s := rr.(*dns.SMIMEA)
		if s.Selector != 0 || s.MatchingType != 0 || (s.Usage != 1 && s.Usage != 3) {
			continue
		}
		der, err := hex.DecodeString(s.Certificate)
		if err != nil {
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil || !smime.Usable(c) {
			continue
		}
		if s.Usage == 1 {
			if r.SMIMERoots == nil {
				continue
			}
			if _, err := c.Verify(x509.VerifyOptions{Roots: r.SMIMERoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}); err != nil {
				continue
			}
		}
		l.Data = der
		break
	}
	return l, nil
}
