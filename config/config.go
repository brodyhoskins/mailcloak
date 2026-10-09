// Package config loads mailcloak.yaml, the single configuration file shared
// by both filters. Shared settings (keys, state, discovery) are top-level;
// each filter's own settings live under "encrypt:" or "decrypt:".
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/brodyhoskins/mailcloak/dnssec"
)

// DefaultPath is the system-wide config file. Packagers can change it at
// build time, e.g. for FreeBSD:
//
//	go build -ldflags "-X github.com/brodyhoskins/mailcloak/config.DefaultPath=/usr/local/etc/mailcloak/mailcloak.yaml"
var DefaultPath = "/etc/mailcloak/mailcloak.yaml"

// ResolvConf is where the default DNS resolver is read from.
var ResolvConf = "/etc/resolv.conf"

// Locate finds the config file. In order: the -config flag, $MAILCLOAK_CONFIG,
// systemd's $CONFIGURATION_DIRECTORY, the XDG config directory (only when not
// running as root, and only if the file exists there), then DefaultPath.
// The flag and $MAILCLOAK_CONFIG are used even if the file is missing, so a
// typo is an error rather than silently falling through. It returns "" if no
// file is found; how says which rule matched.
func Locate(flag string) (path, how string) {
	if flag != "" {
		return flag, "-config"
	}
	if p := os.Getenv("MAILCLOAK_CONFIG"); p != "" {
		return p, "$MAILCLOAK_CONFIG"
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	if d := firstDir(os.Getenv("CONFIGURATION_DIRECTORY")); d != "" {
		if p := filepath.Join(d, "mailcloak.yaml"); exists(p) {
			return p, "$CONFIGURATION_DIRECTORY"
		}
	}
	if os.Geteuid() != 0 {
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir == "" {
			if home, err := os.UserHomeDir(); err == nil {
				dir = filepath.Join(home, ".config")
			}
		}
		if dir != "" {
			if p := filepath.Join(dir, "mailcloak", "mailcloak.yaml"); exists(p) {
				return p, "XDG config directory"
			}
		}
	}
	if exists(DefaultPath) {
		return DefaultPath, "default"
	}
	return "", "none"
}

// firstDir returns the first entry of a colon-separated systemd directory
// variable (systemd lists several when a unit declares several).
func firstDir(v string) string {
	d, _, _ := strings.Cut(v, ":")
	return d
}

type Config struct {
	Hostname string `yaml:"hostname"`
	Keys     Keys   `yaml:"keys"`
	// StateDir holds discovered and harvested keys, shared by both filters.
	// Required for Autocrypt and S/MIME harvesting; optional cache for WKD.
	// Defaults to systemd's $STATE_DIRECTORY when set.
	StateDir  string    `yaml:"state_dir"`
	Discovery Discovery `yaml:"discovery"`
	DNS       DNS       `yaml:"dns"`
	Sendmail  Sendmail  `yaml:"sendmail"`

	// Log is "syslog", "stderr", "none" or a file path. Empty means stderr,
	// except when output goes to the MTA in one-shot mode (stderr is then the
	// delivery status text) where logs go to syslog.
	Log             string        `yaml:"log"`
	MaxMessageBytes int64         `yaml:"max_message_bytes"`
	Timeout         time.Duration `yaml:"timeout"` // per message

	Encrypt Encrypt `yaml:"encrypt"`
	Decrypt Decrypt `yaml:"decrypt"`
}

type Keys struct {
	PGP struct {
		Dir            string `yaml:"dir"`
		PassphraseFile string `yaml:"passphrase_file"`
	} `yaml:"pgp"`
	SMIME struct {
		Dir string `yaml:"dir"`
	} `yaml:"smime"`
}

// Discovery configures finding keys beyond the local directories.
type Discovery struct {
	WKD        *bool  `yaml:"wkd"`        // Web Key Directory; default true
	OPENPGPKEY *bool  `yaml:"openpgpkey"` // DNSSEC OPENPGPKEY records (RFC 7929); default true
	SMIMEA     *bool  `yaml:"smimea"`     // DNSSEC SMIMEA records (RFC 8162); default true
	Keyserver  string `yaml:"keyserver"`  // VKS base URL, e.g. https://keys.openpgp.org; empty = off
	// Autocrypt: decrypt harvests Autocrypt headers, encrypt uses the keys.
	Autocrypt              bool  `yaml:"autocrypt"`
	AutocryptRequireMutual *bool `yaml:"autocrypt_require_mutual"` // default true
	// SMIMEHarvest: decrypt collects certificates from CA-verified signed
	// mail, encrypt uses them. Default: on whenever state_dir is set.
	SMIMEHarvest *bool         `yaml:"smime_harvest"`
	SMIMECAFile  string        `yaml:"smime_ca_file"` // extra roots, added to the system pool
	Timeout      time.Duration `yaml:"timeout"`       // per lookup; default 5s
	CacheTTL     time.Duration `yaml:"cache_ttl"`     // default 24h
	NegativeTTL  time.Duration `yaml:"negative_ttl"`  // default 1h
}

// DNS configures the resolver used for every lookup mailcloak makes itself
// (WKD and keyserver hostnames, OPENPGPKEY, SMIMEA). It must be a
// DNSSEC-validating resolver; mailcloak trusts its AD bit.
type DNS struct {
	// Resolver is host:port. Default: the first nameserver in
	// /etc/resolv.conf, re-read when it changes.
	Resolver string `yaml:"resolver"`
	// TrustedNetworks are CIDRs (or bare IPs) whose resolvers are trusted in
	// addition to loopback. The AD bit can be forged between a remote
	// resolver and mailcloak, so list only networks whose path you trust,
	// e.g. Tailscale's MagicDNS address. Lookups through any other resolver
	// fail.
	TrustedNetworks []string `yaml:"trusted_networks"`
}

// Networks parses TrustedNetworks.
func (d DNS) Networks() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range d.TrustedNetworks {
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("config: dns.trusted_networks: %w", err)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("config: dns.trusted_networks: %w", err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Sendmail configures the "sendmail" output.
type Sendmail struct {
	Path string   `yaml:"path"` // default /usr/sbin/sendmail
	Args []string `yaml:"args"` // before -f; default ["-G", "-i"] (Postfix)
}

// IO is how one filter receives and emits mail.
type IO struct {
	// Listen enables daemon mode: "unix:/path" or "host:port". Without it the
	// filter reads one message from stdin.
	Listen string `yaml:"listen"`
	// Protocol is "lmtp" or "smtp". Defaults to lmtp on UNIX sockets (Postfix's
	// smtp client can't use them) and smtp on TCP.
	Protocol   string `yaml:"protocol"`
	SocketMode string `yaml:"socket_mode"` // octal, default 0660
	// Output: "-" (stdout, default), "sendmail", "smtp:host:port", "smtp:unix:/path".
	Output string `yaml:"output"`
}

type Encrypt struct {
	IO           `yaml:",inline"`
	Mode         string   `yaml:"mode"`          // opportunistic | strict
	Prefer       []string `yaml:"prefer"`        // [pgp, smime]
	LocalDomains []string `yaml:"local_domains"` // never encrypted
	// StrictSources are the key sources that count in strict mode.
	StrictSources []string `yaml:"strict_sources"` // default [local, wkd, openpgpkey, smimea, smime-harvest]
	Autocrypt     struct {
		Advertise     *bool  `yaml:"advertise"`      // default true
		PreferEncrypt string `yaml:"prefer_encrypt"` // mutual (default) | nopreference
	} `yaml:"autocrypt"`
}

type Decrypt struct {
	IO `yaml:",inline"`
}

// Overrides are command-line settings applied on top of the file.
type Overrides struct {
	PGPDir, SMIMEDir, StateDir, Listen, Output string
}

var knownSources = []string{"local", "wkd", "openpgpkey", "smimea", "smime-harvest", "autocrypt", "keyserver"}

// Load reads path (empty for none), applies o to the shared settings and to
// the IO of filter ("encrypt" or "decrypt"), and validates what that filter
// needs.
func Load(path, filter string, o Overrides) (*Config, error) {
	var c Config
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	fio := c.IO(filter)
	if fio == nil {
		return nil, fmt.Errorf("config: unknown filter %q", filter)
	}
	set(&c.Keys.PGP.Dir, o.PGPDir)
	set(&c.Keys.SMIME.Dir, o.SMIMEDir)
	set(&c.StateDir, o.StateDir)
	set(&fio.Listen, o.Listen)
	set(&fio.Output, o.Output)

	if c.StateDir == "" {
		c.StateDir = firstDir(os.Getenv("STATE_DIRECTORY"))
	}
	if err := c.expandPaths(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if err := c.validate(filter); err != nil {
		return nil, err
	}
	return &c, nil
}

// expandPaths expands ${VAR} in path-valued settings, e.g.
// "unix:${RUNTIME_DIRECTORY}/encrypt.sock" under systemd. An unset variable
// is an error rather than an empty string.
func (c *Config) expandPaths() error {
	var missing []string
	expand := func(p *string) {
		*p = os.Expand(*p, func(name string) string {
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return v
		})
	}
	for _, p := range []*string{
		&c.Keys.PGP.Dir, &c.Keys.PGP.PassphraseFile, &c.Keys.SMIME.Dir,
		&c.StateDir, &c.Discovery.SMIMECAFile, &c.Sendmail.Path, &c.Log,
		&c.Encrypt.Listen, &c.Encrypt.Output, &c.Decrypt.Listen, &c.Decrypt.Output,
	} {
		expand(p)
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: environment variable(s) not set: %s", strings.Join(slices.Compact(missing), ", "))
	}
	return nil
}

// NetworkDiscovery reports whether any lookup that touches DNS is enabled.
func (c *Config) NetworkDiscovery() bool {
	d := c.Discovery
	return *d.WKD || *d.OPENPGPKEY || *d.SMIMEA || d.Keyserver != ""
}

func set(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

// IO returns the IO settings of the named filter.
func (c *Config) IO(filter string) *IO {
	switch filter {
	case "encrypt":
		return &c.Encrypt.IO
	case "decrypt":
		return &c.Decrypt.IO
	}
	return nil
}

func boolPtr(b bool) *bool { return &b }

func (c *Config) applyDefaults() {
	if c.Hostname == "" {
		c.Hostname, _ = os.Hostname()
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 50 << 20
	}
	if c.Timeout == 0 {
		c.Timeout = 2 * time.Minute
	}
	if c.Sendmail.Path == "" {
		c.Sendmail.Path = "/usr/sbin/sendmail"
	}
	if c.Sendmail.Args == nil {
		c.Sendmail.Args = []string{"-G", "-i"} // Postfix: gateway submission, no dot handling
	}

	d := &c.Discovery
	if d.WKD == nil {
		d.WKD = boolPtr(true)
	}
	if d.OPENPGPKEY == nil {
		d.OPENPGPKEY = boolPtr(true)
	}
	if d.SMIMEA == nil {
		d.SMIMEA = boolPtr(true)
	}
	if d.SMIMEHarvest == nil {
		d.SMIMEHarvest = boolPtr(c.StateDir != "")
	}
	if d.AutocryptRequireMutual == nil {
		d.AutocryptRequireMutual = boolPtr(true)
	}
	if d.Timeout == 0 {
		d.Timeout = 5 * time.Second
	}
	if d.CacheTTL == 0 {
		d.CacheTTL = 24 * time.Hour
	}
	if d.NegativeTTL == 0 {
		d.NegativeTTL = time.Hour
	}

	for _, fio := range []*IO{&c.Encrypt.IO, &c.Decrypt.IO} {
		if fio.Protocol == "" {
			fio.Protocol = "smtp"
			if strings.HasPrefix(fio.Listen, "unix:") {
				fio.Protocol = "lmtp"
			}
		}
		if fio.SocketMode == "" {
			fio.SocketMode = "0660"
		}
		if fio.Output == "" {
			fio.Output = "-"
		}
	}

	e := &c.Encrypt
	if e.Mode == "" {
		e.Mode = "opportunistic"
	}
	if len(e.Prefer) == 0 {
		e.Prefer = []string{"pgp", "smime"}
	}
	if e.StrictSources == nil {
		e.StrictSources = []string{"local", "wkd", "openpgpkey", "smimea", "smime-harvest"}
	}
	if e.Autocrypt.Advertise == nil {
		e.Autocrypt.Advertise = boolPtr(true)
	}
	if e.Autocrypt.PreferEncrypt == "" {
		e.Autocrypt.PreferEncrypt = "mutual"
	}
}

func (c *Config) validate(filter string) error {
	if c.Keys.PGP.Dir == "" && c.Keys.SMIME.Dir == "" {
		return fmt.Errorf("config: no keys configured (keys.pgp.dir or keys.smime.dir)")
	}
	if (c.Discovery.Autocrypt || *c.Discovery.SMIMEHarvest) && c.StateDir == "" {
		return fmt.Errorf("config: discovery.autocrypt and discovery.smime_harvest need state_dir")
	}

	if c.NetworkDiscovery() {
		if err := c.checkResolver(); err != nil {
			return err
		}
	}

	fio := c.IO(filter)
	if fio.Protocol != "lmtp" && fio.Protocol != "smtp" {
		return fmt.Errorf("config: %s.protocol must be lmtp or smtp", filter)
	}
	if _, err := fio.SocketFileMode(); err != nil {
		return fmt.Errorf("config: %s.%w", filter, err)
	}
	switch {
	case fio.Output == "-", fio.Output == "sendmail":
	case strings.HasPrefix(fio.Output, "smtp:") && len(fio.Output) > len("smtp:"):
	default:
		return fmt.Errorf("config: %s.output must be -, sendmail, smtp:host:port or smtp:unix:/path", filter)
	}
	if fio.Listen != "" && fio.Output == "-" {
		return fmt.Errorf("config: %s: daemon mode (listen) needs an output other than stdout", filter)
	}

	if filter == "encrypt" {
		e := c.Encrypt
		if e.Mode != "opportunistic" && e.Mode != "strict" {
			return fmt.Errorf("config: encrypt.mode must be opportunistic or strict")
		}
		for _, p := range e.Prefer {
			if p != "pgp" && p != "smime" {
				return fmt.Errorf("config: encrypt.prefer: unknown method %q", p)
			}
		}
		for _, s := range e.StrictSources {
			if !slices.Contains(knownSources, s) {
				return fmt.Errorf("config: encrypt.strict_sources: unknown source %q (want one of %s)", s, strings.Join(knownSources, ", "))
			}
		}
		if p := e.Autocrypt.PreferEncrypt; p != "mutual" && p != "nopreference" {
			return fmt.Errorf("config: encrypt.autocrypt.prefer_encrypt must be mutual or nopreference")
		}
	}
	return nil
}

// SocketFileMode parses SocketMode as an octal permission.
func (fio *IO) SocketFileMode() (os.FileMode, error) {
	m, err := strconv.ParseUint(fio.SocketMode, 8, 32)
	if err != nil || m > 0o777 {
		return 0, fmt.Errorf("socket_mode %q is not an octal permission", fio.SocketMode)
	}
	return os.FileMode(m), nil
}

// checkResolver validates the DNS settings. A resolver given explicitly must
// be trusted; one taken from resolv.conf is checked at each lookup instead,
// since it can change while mailcloak runs (e.g. a VPN coming up).
func (c *Config) checkResolver() error {
	nets, err := c.DNS.Networks()
	if err != nil {
		return err
	}
	if c.DNS.Resolver == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(c.DNS.Resolver)
	if err != nil {
		return fmt.Errorf("config: dns.resolver: %w", err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("config: dns.resolver must be an IP address and port, got %q", c.DNS.Resolver)
	}
	if !dnssec.Trusted(c.DNS.Resolver, nets) {
		return fmt.Errorf("config: dns.resolver %s is neither loopback nor in dns.trusted_networks; "+
			"mailcloak can only trust DNSSEC results from a resolver it can reach safely", c.DNS.Resolver)
	}
	return nil
}
