package filter

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/brodyhoskins/mailcloak/config"
	"github.com/brodyhoskins/mailcloak/discover"
	"github.com/brodyhoskins/mailcloak/dnssec"
	"github.com/brodyhoskins/mailcloak/fetch"
	"github.com/brodyhoskins/mailcloak/hooks"
	"github.com/brodyhoskins/mailcloak/internal/version"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/pipeline"
	"github.com/brodyhoskins/mailcloak/smime"
)

// Encrypt builds mailcloak-encrypt.
func Encrypt(cfg *config.Config, log *slog.Logger) (pipeline.Middleware, error) {
	p, s, err := loadEngines(cfg.Keys, log)
	if err != nil {
		return nil, err
	}
	e := cfg.Encrypt
	var strict []discover.Source
	for _, src := range e.StrictSources {
		strict = append(strict, discover.Source(src))
	}
	keys, err := resolver(cfg, p, s, log)
	if err != nil {
		return nil, err
	}
	h := &hooks.Encrypt{
		PGP:                p,
		SMIME:              s,
		Keys:               keys,
		Prefer:             e.Prefer,
		Mode:               hooks.Mode(e.Mode),
		LocalDomains:       e.LocalDomains,
		StrictSources:      strict,
		AdvertiseAutocrypt: *e.Autocrypt.Advertise,
		PreferEncrypt:      e.Autocrypt.PreferEncrypt,
		Log:                log,
	}
	return h.Middleware, nil
}

// Decrypt builds mailcloak-decrypt.
func Decrypt(cfg *config.Config, log *slog.Logger) (pipeline.Middleware, error) {
	p, s, err := loadEngines(cfg.Keys, log)
	if err != nil {
		return nil, err
	}
	h := &hooks.Decrypt{PGP: p, SMIME: s, Log: log}
	d := cfg.Discovery
	if d.Autocrypt || *d.SMIMEHarvest {
		h.Harvest = &discover.Harvester{
			Store:     store(cfg),
			Autocrypt: d.Autocrypt,
			SMIME:     *d.SMIMEHarvest,
			Log:       log,
		}
		if *d.SMIMEHarvest {
			if h.Harvest.SMIMERoots, err = smimeRoots(d.SMIMECAFile); err != nil {
				return nil, err
			}
		}
	}
	return h.Middleware, nil
}

func store(cfg *config.Config) *discover.Store {
	if cfg.StateDir == "" {
		return nil
	}
	return &discover.Store{Dir: filepath.Join(cfg.StateDir, "keys")}
}

func resolver(cfg *config.Config, p *pgp.Engine, s *smime.Engine, log *slog.Logger) (*discover.Resolver, error) {
	d := cfg.Discovery
	r := &discover.Resolver{
		PGP:           p,
		SMIME:         s,
		Store:         store(cfg),
		WKD:           *d.WKD,
		OPENPGPKEY:    *d.OPENPGPKEY,
		SMIMEA:        *d.SMIMEA,
		Keyserver:     d.Keyserver,
		Autocrypt:     d.Autocrypt,
		RequireMutual: *d.AutocryptRequireMutual,
		SMIMEHarvest:  *d.SMIMEHarvest,
		Timeout:       d.Timeout,
		CacheTTL:      d.CacheTTL,
		NegativeTTL:   d.NegativeTTL,
		Log:           log,
	}
	if cfg.NetworkDiscovery() {
		// Every name mailcloak resolves goes through the validating resolver,
		// including the hostnames of HTTPS key servers.
		nets, err := cfg.DNS.Networks()
		if err != nil {
			return nil, err
		}
		r.DNS = &dnssec.Resolver{Addr: cfg.DNS.Resolver, ResolvConf: config.ResolvConf, Trusted: nets, Timeout: d.Timeout}
		if _, err := r.DNS.Current(); err != nil {
			// Not fatal: the resolver may change (a VPN coming up). Until it
			// does, DNS-based lookups fail: strict mode defers, opportunistic
			// mode sends signed only.
			log.Warn("key discovery unavailable with the current resolver", "err", err)
		}
		r.HTTP = &fetch.Client{
			HTTP:      &http.Client{Transport: fetch.NewTransport(r.DNS.DialContext), Timeout: d.Timeout},
			MaxBody:   512 << 10,
			UserAgent: version.Token(),
		}
	}
	if *d.SMIMEA {
		var err error
		if r.SMIMERoots, err = smimeRoots(d.SMIMECAFile); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// smimeRoots is the system trust store plus any extra CA file.
func smimeRoots(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("smime_ca_file %s: no certificates", caFile)
		}
	}
	return pool, nil
}

// loadEngines loads the PGP and S/MIME engines named in keys. Either may be
// nil if its directory is not configured.
func loadEngines(keys config.Keys, log *slog.Logger) (*pgp.Engine, *smime.Engine, error) {
	var p *pgp.Engine
	if dir := keys.PGP.Dir; dir != "" {
		var pass []byte
		if f := keys.PGP.PassphraseFile; f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, nil, err
			}
			pass = bytes.TrimRight(b, "\r\n")
		}
		var err error
		if p, err = pgp.Load(dir, pass, log); err != nil {
			return nil, nil, err
		}
	}
	var s *smime.Engine
	if dir := keys.SMIME.Dir; dir != "" {
		var err error
		if s, err = smime.Load(dir, log); err != nil {
			return nil, nil, err
		}
	}
	return p, s, nil
}
