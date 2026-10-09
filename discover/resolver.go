package discover

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/brodyhoskins/mailcloak/dnssec"
	"github.com/brodyhoskins/mailcloak/fetch"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/smime"
)

// Source says where a recipient's key came from. Strict mode can be limited
// to trusted sources.
type Source string

const (
	SourceLocal        Source = "local"         // the configured key directories
	SourceWKD          Source = "wkd"           // the recipient's domain, over HTTPS
	SourceOPENPGPKEY   Source = "openpgpkey"    // the recipient's domain, DNSSEC (RFC 7929)
	SourceSMIMEA       Source = "smimea"        // the recipient's domain, DNSSEC (RFC 8162)
	SourceSMIMEHarvest Source = "smime-harvest" // a CA-verified signature on incoming mail
	SourceAutocrypt    Source = "autocrypt"     // an Autocrypt header (trust on first use)
	SourceKeyserver    Source = "keyserver"     // a third-party keyserver
)

// Store kinds.
const (
	kindWKD        = "wkd"
	kindOPENPGPKEY = "openpgpkey"
	kindSMIMEA     = "smimea"
	kindKeyserver  = "keyserver"
	kindAutocrypt  = "autocrypt"
	kindSMIME      = "smime"
)

// autocryptStale is how long after the last Autocrypt header a peer may keep
// sending mail without one before its key is no longer used (Autocrypt
// Level 1 "discourage" rule).
const autocryptStale = 35 * 24 * time.Hour

// maxFreshness caps how long a server or DNS TTL can make us skip
// revalidation.
const maxFreshness = 7 * 24 * time.Hour

type PGPKey struct {
	Entity *openpgp.Entity
	Source Source
}

type SMIMECert struct {
	Cert   *x509.Certificate
	Source Source
}

// Resolver finds a recipient's key. A key placed locally always wins; after
// that, sources the recipient's own domain publishes come before learned
// and third-party ones:
//
//	PGP:    local, WKD, OPENPGPKEY, Autocrypt, keyserver
//	S/MIME: local, SMIMEA, harvested
type Resolver struct {
	PGP   *pgp.Engine
	SMIME *smime.Engine
	Store *Store // nil disables caching and harvested keys

	WKD           bool
	OPENPGPKEY    bool
	SMIMEA        bool
	Keyserver     string // base URL; empty disables
	Autocrypt     bool
	RequireMutual bool // only use Autocrypt keys whose owner set prefer-encrypt=mutual
	SMIMEHarvest  bool

	HTTP       *fetch.Client
	DNS        *dnssec.Resolver // required for OPENPGPKEY and SMIMEA
	SMIMERoots *x509.CertPool   // for SMIMEA usage 1 (PKIX-EE)

	Timeout     time.Duration // per lookup
	CacheTTL    time.Duration // freshness of a found key when the source doesn't say
	NegativeTTL time.Duration // freshness of "no key" when the source doesn't say
	Log         *slog.Logger
	Now         func() time.Time
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// PGPKey returns a key for addr, or nil if there is none. An error means a
// lookup failed and no other source had a key, so the answer is unknown.
func (r *Resolver) PGPKey(ctx context.Context, addr string) (*PGPKey, error) {
	if r.PGP != nil {
		if e := r.PGP.LocalKey(addr); e != nil {
			return &PGPKey{e, SourceLocal}, nil
		}
	}
	var errs []error
	try := func(on bool, kind string, src Source, fn lookupFunc) *PGPKey {
		if !on {
			return nil
		}
		data, err := r.cached(ctx, kind, addr, fn)
		errs = append(errs, err)
		if e := selectKey(data, addr); e != nil {
			return &PGPKey{e, src}
		}
		return nil
	}
	if k := try(r.WKD, kindWKD, SourceWKD, r.lookupWKD); k != nil {
		return k, nil
	}
	if k := try(r.OPENPGPKEY && r.DNS != nil, kindOPENPGPKEY, SourceOPENPGPKEY, r.lookupOPENPGPKEY); k != nil {
		return k, nil
	}
	if r.Autocrypt && r.Store != nil {
		if e := r.autocryptKey(addr); e != nil {
			return &PGPKey{e, SourceAutocrypt}, nil
		}
	}
	if k := try(r.Keyserver != "", kindKeyserver, SourceKeyserver, r.lookupKeyserver); k != nil {
		return k, nil
	}
	return nil, errors.Join(errs...)
}

// SMIMECert returns a certificate for addr, or nil if there is none. An
// error means a lookup failed and nothing else was found.
func (r *Resolver) SMIMECert(ctx context.Context, addr string) (*SMIMECert, error) {
	if r.SMIME != nil {
		if c := r.SMIME.LocalCert(addr); c != nil {
			return &SMIMECert{c, SourceLocal}, nil
		}
	}
	var lookupErr error
	if r.SMIMEA && r.DNS != nil {
		der, err := r.cached(ctx, kindSMIMEA, addr, r.lookupSMIMEA)
		lookupErr = err
		if c, err := x509.ParseCertificate(der); len(der) > 0 && err == nil && smime.Usable(c) {
			return &SMIMECert{c, SourceSMIMEA}, nil
		}
	}
	if r.SMIMEHarvest && r.Store != nil {
		var rec harvestedCert
		if ok, err := r.Store.Get(kindSMIME, addr, &rec); err == nil && ok {
			if c, err := x509.ParseCertificate(rec.Cert); err == nil && smime.Usable(c) {
				return &SMIMECert{c, SourceSMIMEHarvest}, nil
			}
		}
	}
	return nil, lookupErr
}

// lookup is what a source returned.
type lookup struct {
	Data        []byte // key or certificate; nil if the source has none
	NotModified bool   // HTTP 304: the cached copy is still valid
	MaxAge      time.Duration
	NoStore     bool
	URL         string
	Validators  fetch.Validators
}

type lookupFunc func(ctx context.Context, addr string, prev *cachedKey) (*lookup, error)

// cachedKey is a cached lookup result. Empty Data records that the source had
// nothing.
type cachedKey struct {
	Addr       string           `json:"addr"`
	Fetched    time.Time        `json:"fetched"`
	FreshUntil time.Time        `json:"fresh_until"`
	URL        string           `json:"url,omitempty"`
	Validators fetch.Validators `json:"validators,omitzero"`
	Data       []byte           `json:"data,omitempty"`
}

// cached returns a source's data for addr. A fresh cache entry is used as is;
// a stale one is revalidated (a conditional request for HTTP sources) and, if
// the source is unreachable, still used rather than nothing.
func (r *Resolver) cached(ctx context.Context, kind, addr string, fn lookupFunc) ([]byte, error) {
	var prev *cachedKey
	if r.Store != nil {
		var rec cachedKey
		ok, err := r.Store.Get(kind, addr, &rec)
		if err != nil {
			r.Log.Warn("discover: cache read failed", "kind", kind, "err", err)
		}
		if ok && err == nil {
			if r.now().Before(rec.FreshUntil) {
				return rec.Data, nil
			}
			prev = &rec
		}
	}

	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	l, err := fn(ctx, addr, prev)
	if err != nil {
		r.Log.Warn("discover: lookup failed", "kind", kind, "addr", addr, "err", err)
		if prev != nil && len(prev.Data) > 0 {
			return prev.Data, nil
		}
		return nil, err
	}

	data := l.Data
	if l.NotModified && prev != nil {
		data = prev.Data
	}
	ttl := r.NegativeTTL
	if len(data) > 0 {
		ttl = r.CacheTTL
	}
	if l.MaxAge >= 0 {
		ttl = min(l.MaxAge, maxFreshness)
	}
	r.Log.Info("discover: lookup", "kind", kind, "addr", addr, "found", len(data) > 0, "not_modified", l.NotModified, "ttl", ttl)

	if r.Store != nil && !l.NoStore {
		now := r.now()
		rec := &cachedKey{Addr: addr, Fetched: now, FreshUntil: now.Add(ttl), URL: l.URL, Validators: l.Validators, Data: data}
		if err := r.Store.Put(kind, addr, rec); err != nil {
			r.Log.Warn("discover: cache write failed", "kind", kind, "err", err)
		}
	}
	return data, nil
}

func (r *Resolver) autocryptKey(addr string) *openpgp.Entity {
	var p autocryptPeer
	if ok, err := r.Store.Get(kindAutocrypt, addr, &p); err != nil || !ok || len(p.Key) == 0 {
		return nil
	}
	if r.RequireMutual && p.PreferEncrypt != "mutual" {
		return nil
	}
	if p.LastSeen.Sub(p.Timestamp) > autocryptStale {
		return nil
	}
	return selectKey(p.Key, addr)
}

func selectKey(data []byte, addr string) *openpgp.Entity {
	if len(data) == 0 {
		return nil
	}
	list, err := pgp.ParseKeys(data)
	if err != nil {
		return nil
	}
	return pgp.SelectKey(list, addr)
}
