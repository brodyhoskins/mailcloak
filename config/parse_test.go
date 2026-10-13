package config

import "testing"

func TestParse(t *testing.T) {
	keys := "keys:\n  pgp:\n    dir: " + t.TempDir() + "\n"
	c, err := Parse([]byte(keys+"state_dir: /var/lib/mailcloak\nencrypt:\n  mode: strict\n"), "encrypt", Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != "/var/lib/mailcloak" || c.Encrypt.Mode != "strict" {
		t.Errorf("got state_dir %q, mode %q", c.StateDir, c.Encrypt.Mode)
	}
	if _, err := Parse([]byte(keys+"no_such_key: 1\n"), "encrypt", Overrides{}); err == nil {
		t.Error("unknown key accepted")
	}
}
