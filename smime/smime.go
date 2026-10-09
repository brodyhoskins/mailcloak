// Package smime implements S/MIME (RFC 8551) signing, encryption and
// decryption on top of a directory of PEM certificates and keys.
package smime

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/brodyhoskins/mailcloak/mimeutil"
)

func init() {
	// The library defaults to DES-CBC. AES-256-CBC is the strongest content
	// cipher with broad client support; key transport stays RSA PKCS#1 v1.5
	// for the same reason.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// Identity is a certificate, its chain, and optionally its private key.
type Identity struct {
	Cert  *x509.Certificate
	Chain []*x509.Certificate
	Key   crypto.PrivateKey
}

// Engine indexes identities by lower-case email address.
type Engine struct {
	byAddr map[string][]*Identity
	all    []*Identity
}

// Load reads every *.crt, *.pem and *.cer file in dir. The first certificate in
// a file is the leaf and the rest are its chain. A private key is loaded from
// a file with the same base name and a .key extension, if present.
func Load(dir string, log *slog.Logger) (*Engine, error) {
	e := &Engine{byAddr: map[string][]*Identity{}}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	keys := 0
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f.Name()))
		if ext != ".crt" && ext != ".pem" && ext != ".cer" {
			continue
		}
		path := filepath.Join(dir, f.Name())
		certs, err := readCerts(path)
		if err != nil {
			return nil, fmt.Errorf("smime: %s: %w", path, err)
		}
		if len(certs) == 0 {
			continue
		}
		id := &Identity{Cert: certs[0], Chain: certs[1:]}
		keyPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".key"
		if _, err := os.Stat(keyPath); err == nil {
			if id.Key, err = readKey(keyPath); err != nil {
				return nil, fmt.Errorf("smime: %s: %w", keyPath, err)
			}
			keys++
		}
		e.all = append(e.all, id)
		for _, a := range addresses(id.Cert) {
			e.byAddr[a] = append(e.byAddr[a], id)
		}
	}
	log.Info("smime: certificates loaded", "certs", len(e.all), "private", keys)
	return e, nil
}

func readCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func readKey(path string) (crypto.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

func addresses(c *x509.Certificate) []string {
	var out []string
	for _, a := range c.EmailAddresses {
		out = append(out, strings.ToLower(a))
	}
	for _, n := range c.Subject.Names {
		if n.Type.Equal(oidEmailAddress) {
			if s, ok := n.Value.(string); ok {
				out = append(out, strings.ToLower(s))
			}
		}
	}
	return out
}

func valid(c *x509.Certificate) bool {
	now := time.Now()
	return now.After(c.NotBefore) && now.Before(c.NotAfter)
}

// LocalCert returns a usable certificate for addr from the certificate directory.
func (e *Engine) LocalCert(addr string) *x509.Certificate {
	for _, id := range e.byAddr[strings.ToLower(addr)] {
		if Usable(id.Cert) {
			return id.Cert
		}
	}
	return nil
}

// Usable reports whether c is currently valid and has an RSA key, the only
// key type the pkcs7 library can encrypt to.
func Usable(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && valid(c)
}

// Addresses returns the email addresses a certificate is issued for.
func Addresses(c *x509.Certificate) []string { return addresses(c) }

func (e *Engine) signer(addr string) *Identity {
	for _, id := range e.byAddr[strings.ToLower(addr)] {
		if id.Key != nil && valid(id.Cert) {
			return id
		}
	}
	return nil
}

// CanSign reports whether a certificate with a private key exists for addr.
func (e *Engine) CanSign(addr string) bool { return e.signer(addr) != nil }

// IsEncrypted reports whether m is an S/MIME enveloped message.
func IsEncrypted(m *mimeutil.Message) bool {
	mt, params := m.Header.MediaType()
	if mt != "application/pkcs7-mime" && mt != "application/x-pkcs7-mime" {
		return false
	}
	st := strings.ToLower(params["smime-type"])
	return st == "enveloped-data" || st == "authenveloped-data" || st == ""
}

// IsSigned reports whether m is already a multipart/signed message.
func IsSigned(m *mimeutil.Message) bool {
	mt, _ := m.Header.MediaType()
	return mt == "multipart/signed"
}

// signEntity wraps a MIME entity in a multipart/signed entity with a detached
// PKCS#7 signature over the exact entity bytes.
func signEntity(id *Identity, entity []byte) ([]byte, error) {
	sd, err := pkcs7.NewSignedData(entity)
	if err != nil {
		return nil, err
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSignerChain(id.Cert, id.Key, id.Chain, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	sd.Detach()
	sig, err := sd.Finish()
	if err != nil {
		return nil, err
	}

	boundary := mimeutil.Boundary()
	var b bytes.Buffer
	fmt.Fprintf(&b, "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\";\r\n\tmicalg=sha-256; boundary=\"%s\"\r\n\r\n", boundary)
	b.WriteString("This is a cryptographically signed message in MIME format.\r\n\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.Write(entity)
	fmt.Fprintf(&b, "\r\n--%s\r\n", boundary)
	b.WriteString("Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\nContent-Description: S/MIME Cryptographic Signature\r\n\r\n")
	b.Write(mimeutil.Base64Lines(sig))
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

// Sign signs m as signer. It returns an error if signer has no key.
func (e *Engine) Sign(m *mimeutil.Message, signer string) ([]byte, error) {
	id := e.signer(signer)
	if id == nil {
		return nil, fmt.Errorf("smime: no signing key for %s", signer)
	}
	outer, entity := m.SplitEntity()
	signed, err := signEntity(id, entity)
	if err != nil {
		return nil, err
	}
	return mimeutil.JoinEntity(outer, signed)
}

// Encrypt encrypts m to certs. If signer has a key the entity is signed first
// (sign-then-encrypt), so the signature is protected by the envelope.
func (e *Engine) Encrypt(m *mimeutil.Message, certs []*x509.Certificate, signer string) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("smime: no recipients")
	}
	outer, entity := m.SplitEntity()
	if signer != "" {
		if id := e.signer(signer); id != nil {
			var err error
			if entity, err = signEntity(id, entity); err != nil {
				return nil, err
			}
		}
	}
	der, err := pkcs7.Encrypt(entity, certs)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7m\"\r\nContent-Description: S/MIME Encrypted Message\r\n\r\n")
	b.Write(mimeutil.Base64Lines(der))
	return mimeutil.JoinEntity(outer, b.Bytes())
}

// ErrNoKey is returned when none of the loaded private keys can decrypt.
var ErrNoKey = errors.New("smime: no matching private key")

// Decrypt decrypts an enveloped message. The decrypted entity is returned
// as-is, so an inner multipart/signed survives for the client to verify.
func (e *Engine) Decrypt(m *mimeutil.Message) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(m.Body), nil)))
	if err != nil {
		return nil, fmt.Errorf("smime: decode body: %w", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, err
	}
	for _, id := range e.all {
		if id.Key == nil {
			continue
		}
		entity, err := p7.Decrypt(id.Cert, id.Key)
		if err != nil {
			continue
		}
		outer, _ := m.SplitEntity()
		return mimeutil.JoinEntity(outer, mimeutil.CRLF(entity))
	}
	return nil, ErrNoKey
}

// VerifySigned checks the S/MIME signature on a multipart/signed message and
// returns the signer's certificate and the chain that came with it. If roots
// is non-nil, the certificate must also chain to it and be valid for email
// protection.
func VerifySigned(m *mimeutil.Message, roots *x509.CertPool) (*x509.Certificate, []*x509.Certificate, error) {
	mt, params := m.Header.MediaType()
	proto := strings.ToLower(params["protocol"])
	if mt != "multipart/signed" || (proto != "application/pkcs7-signature" && proto != "application/x-pkcs7-signature") {
		return nil, nil, errors.New("smime: not an S/MIME signed message")
	}
	delim := []byte("--" + params["boundary"])
	parts := bytes.Split(m.Body, delim)
	// parts: preamble, signed entity, signature part, epilogue ("--").
	if len(parts) < 3 {
		return nil, nil, errors.New("smime: malformed multipart/signed")
	}
	// The CRLF before each delimiter belongs to the delimiter.
	signed := bytes.TrimPrefix(parts[1], []byte("\r\n"))
	signed = bytes.TrimSuffix(signed, []byte("\r\n"))

	sigPart, err := mimeutil.Parse(bytes.TrimPrefix(parts[2], []byte("\r\n")))
	if err != nil {
		return nil, nil, err
	}
	der, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(sigPart.Body), nil)))
	if err != nil {
		return nil, nil, fmt.Errorf("smime: decode signature: %w", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, nil, err
	}
	p7.Content = signed
	if err := p7.Verify(); err != nil {
		return nil, nil, err
	}
	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, nil, errors.New("smime: expected exactly one signer")
	}
	if roots != nil {
		inter := x509.NewCertPool()
		for _, c := range p7.Certificates {
			inter.AddCert(c)
		}
		if _, err := signer.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		}); err != nil {
			return nil, nil, err
		}
	}
	var chain []*x509.Certificate
	for _, c := range p7.Certificates {
		if !c.Equal(signer) {
			chain = append(chain, c)
		}
	}
	return signer, chain, nil
}
