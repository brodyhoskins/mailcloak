package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolvConf points ResolvConf at a file naming server for this test.
func resolvConf(t *testing.T, server string) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(p, []byte("nameserver "+server+"\n"), 0o644)
	old := ResolvConf
	ResolvConf = p
	t.Cleanup(func() { ResolvConf = old })
}

func load(t *testing.T, yaml string) (*Config, error) {
	if ResolvConf == "/etc/resolv.conf" {
		resolvConf(t, "127.0.0.1")
	}
	p := filepath.Join(t.TempDir(), "mailcloak.yaml")
	if err := os.WriteFile(p, []byte("keys:\n  pgp:\n    dir: /k\n"+yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(p, "encrypt", Overrides{})
}

func TestSMIMEHarvestDefault(t *testing.T) {
	c, err := load(t, "")
	if err != nil || *c.Discovery.SMIMEHarvest {
		t.Fatalf("without state_dir harvesting should be off, not an error: %v", err)
	}
	c, err = load(t, "state_dir: /var/lib/mailcloak\n")
	if err != nil || !*c.Discovery.SMIMEHarvest {
		t.Fatalf("with state_dir harvesting should default on: %v", err)
	}
	c, err = load(t, "state_dir: /var/lib/mailcloak\ndiscovery:\n  smime_harvest: false\n")
	if err != nil || *c.Discovery.SMIMEHarvest {
		t.Fatalf("explicit false must be respected: %v", err)
	}
	if _, err = load(t, "discovery:\n  smime_harvest: true\n"); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("explicit true without state_dir must be an error, got %v", err)
	}
}

func TestUnknownFieldsRejected(t *testing.T) {
	if _, err := load(t, "encrypt:\n  mdoe: strict\n"); err == nil {
		t.Fatal("typo in config accepted")
	}
}

func TestResolverTrust(t *testing.T) {
	// A resolver from resolv.conf is checked per lookup, not at startup.
	resolvConf(t, "192.168.1.1")
	if _, err := load(t, ""); err != nil {
		t.Fatalf("resolv.conf resolver must not be a startup error: %v", err)
	}
	// An explicit resolver must be trusted.
	if _, err := load(t, "dns:\n  resolver: 192.168.1.1:53\n"); err == nil || !strings.Contains(err.Error(), "trusted_networks") {
		t.Fatalf("untrusted explicit resolver accepted: %v", err)
	}
	if _, err := load(t, "dns:\n  resolver: 127.0.0.53:53\n"); err != nil {
		t.Fatalf("loopback resolver rejected: %v", err)
	}
	ts := "dns:\n  resolver: 100.100.100.100:53\n  trusted_networks: [100.100.100.100, \"fd7a:115c:a1e0::53/128\"]\n"
	if c, err := load(t, ts); err != nil {
		t.Fatalf("resolver in trusted_networks rejected: %v", err)
	} else if n, _ := c.DNS.Networks(); len(n) != 2 || n[0].Bits() != 32 {
		t.Fatalf("networks parsed as %v", n)
	}
	if _, err := load(t, "dns:\n  trusted_networks: [100.64.0.0/33]\n"); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}

func TestLocate(t *testing.T) {
	dir := t.TempDir()
	write := func(p string) string {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, nil, 0o644)
		return p
	}
	def := write(filepath.Join(dir, "etc", "mailcloak.yaml"))
	old := DefaultPath
	DefaultPath = def
	t.Cleanup(func() { DefaultPath = old })
	t.Setenv("MAILCLOAK_CONFIG", "")
	t.Setenv("CONFIGURATION_DIRECTORY", "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))

	if p, _ := Locate(""); p != def {
		t.Errorf("default: %s", p)
	}
	xdg := write(filepath.Join(dir, "xdg", "mailcloak", "mailcloak.yaml"))
	if p, _ := Locate(""); p != xdg && os.Geteuid() != 0 {
		t.Errorf("XDG: %s", p)
	}
	sd := filepath.Join(dir, "systemd")
	sdFile := write(filepath.Join(sd, "mailcloak.yaml"))
	t.Setenv("CONFIGURATION_DIRECTORY", sd+":/other")
	if p, how := Locate(""); p != sdFile {
		t.Errorf("systemd: %s (%s)", p, how)
	}
	t.Setenv("MAILCLOAK_CONFIG", "/missing/is/still/used.yaml")
	if p, _ := Locate(""); p != "/missing/is/still/used.yaml" {
		t.Errorf("env: %s", p)
	}
	if p, how := Locate("/flag.yaml"); p != "/flag.yaml" || how != "-config" {
		t.Errorf("flag: %s", p)
	}
}

func TestPathExpansionAndStateDirectory(t *testing.T) {
	t.Setenv("RUNTIME_DIRECTORY", "/run/mailcloak")
	t.Setenv("STATE_DIRECTORY", "/var/lib/mailcloak:/var/lib/other")
	c, err := load(t, "encrypt:\n  listen: unix:${RUNTIME_DIRECTORY}/encrypt.sock\n  output: sendmail\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Encrypt.Listen != "unix:/run/mailcloak/encrypt.sock" {
		t.Errorf("listen = %s", c.Encrypt.Listen)
	}
	if c.StateDir != "/var/lib/mailcloak" || !*c.Discovery.SMIMEHarvest {
		t.Errorf("state_dir = %q, harvest %v", c.StateDir, *c.Discovery.SMIMEHarvest)
	}
	if _, err := load(t, "state_dir: ${NOT_SET_ANYWHERE}/x\n"); err == nil || !strings.Contains(err.Error(), "NOT_SET_ANYWHERE") {
		t.Fatalf("unset variable must be an error: %v", err)
	}
}
