// Package testkeys generates throwaway PGP keys and S/MIME certificates into
// directories laid out the way the engines expect. For tests only.
package testkeys

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// NewPGP generates an Ed25519/Cv25519 key for email (fast, and the usual
// Autocrypt key type).
func NewPGP(t testing.TB, email string) *openpgp.Entity {
	t.Helper()
	ent, err := openpgp.NewEntity(email, "", email, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519})
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

// PublicBytes returns the binary public key of ent.
func PublicBytes(t testing.TB, ent *openpgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := ent.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// PGP writes a key for email into dir; private controls whether the secret
// key is included.
func PGP(t testing.TB, dir, email string, private bool) {
	t.Helper()
	ent := NewPGP(t, email)
	f, err := os.Create(filepath.Join(dir, email+".asc"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	typ := "PGP PUBLIC KEY BLOCK"
	if private {
		typ = "PGP PRIVATE KEY BLOCK"
	}
	w, err := armor.Encode(f, typ, nil)
	if err != nil {
		t.Fatal(err)
	}
	if private {
		err = ent.SerializePrivate(w, nil)
	} else {
		err = ent.Serialize(w)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// SMIME writes a self-signed certificate (and key, if private) for email into dir.
func SMIME(t testing.TB, dir, email string, private bool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, typ string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(email+".crt", "CERTIFICATE", der)
	if private {
		write(email+".key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	}
}
