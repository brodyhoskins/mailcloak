package hooks

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// copyPublic copies only the public half of a key file from src to dst.
func copyPublic(t *testing.T, src, dst, name string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(src, name))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(name) == ".crt" {
		blk, _ := pem.Decode(b)
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	ents, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, _ := armor.Encode(&out, "PGP PUBLIC KEY BLOCK", nil)
	for _, e := range ents {
		if err := e.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	if err := os.WriteFile(filepath.Join(dst, name), out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
