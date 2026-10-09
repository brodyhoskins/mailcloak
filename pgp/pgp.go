// Package pgp implements PGP/MIME (RFC 3156) encryption, signing and
// decryption on top of a directory-backed keyring.
package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/brodyhoskins/mailcloak/mimeutil"
)

// Engine holds the loaded keys. Public keys are used to encrypt to recipients
// and verify signatures; private keys are used to sign and decrypt.
type Engine struct {
	public  openpgp.EntityList // every entity, for encryption and verification
	private openpgp.EntityList // entities with usable (unlocked) private keys
}

// Load reads every *.asc, *.gpg and *.pgp file in dir. Encrypted private keys
// are unlocked with passphrase; if it is empty they are kept as public only.
func Load(dir string, passphrase []byte, log *slog.Logger) (*Engine, error) {
	e := &Engine{}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		switch strings.ToLower(filepath.Ext(f.Name())) {
		case ".asc", ".gpg", ".pgp":
		default:
			continue
		}
		path := filepath.Join(dir, f.Name())
		ents, err := readKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("pgp: %s: %w", path, err)
		}
		for _, ent := range ents {
			e.public = append(e.public, ent)
			if ent.PrivateKey == nil {
				continue
			}
			if ent.PrivateKey.Encrypted {
				if len(passphrase) == 0 {
					log.Warn("pgp: skipping locked private key (no passphrase configured)", "file", path)
					continue
				}
				if err := ent.DecryptPrivateKeys(passphrase); err != nil {
					return nil, fmt.Errorf("pgp: %s: unlock private key: %w", path, err)
				}
			}
			e.private = append(e.private, ent)
		}
	}
	log.Info("pgp: keys loaded", "entities", len(e.public), "private", len(e.private))
	return e, nil
}

func readKeyFile(path string) (openpgp.EntityList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKeys(b)
}

func hasEmail(ent *openpgp.Entity, addr string) bool {
	for _, id := range ent.Identities {
		if id.UserId != nil && strings.EqualFold(id.UserId.Email, addr) {
			return true
		}
	}
	return false
}

// LocalKey returns a valid encryption key for addr from the key directory.
func (e *Engine) LocalKey(addr string) *openpgp.Entity { return SelectKey(e.public, addr) }

// SelectKey returns the first entity in list with a user ID for addr, that is
// not revoked and has a usable encryption key.
func SelectKey(list openpgp.EntityList, addr string) *openpgp.Entity {
	now := time.Now()
	for _, ent := range list {
		if hasEmail(ent, addr) && !ent.Revoked(now) {
			if _, ok := ent.EncryptionKey(now); ok {
				return ent
			}
		}
	}
	return nil
}

// AutocryptKey returns addr's public key reduced to what Autocrypt asks for:
// the primary key, the user ID for addr, and one encryption subkey.
func (e *Engine) AutocryptKey(addr string) ([]byte, bool) {
	ent := e.signingKey(addr)
	if ent == nil {
		return nil, false
	}
	enc, ok := ent.EncryptionKey(time.Now())
	if !ok {
		return nil, false
	}
	min := &openpgp.Entity{
		PrimaryKey:    ent.PrimaryKey,
		Revocations:   ent.Revocations,
		SelfSignature: ent.SelfSignature,
		Signatures:    ent.Signatures,
		Identities:    map[string]*openpgp.Identity{},
	}
	for name, id := range ent.Identities {
		if id.UserId != nil && strings.EqualFold(id.UserId.Email, addr) {
			min.Identities[name] = id
			break
		}
	}
	for _, sk := range ent.Subkeys {
		if sk.PublicKey == enc.PublicKey {
			min.Subkeys = []openpgp.Subkey{{PublicKey: sk.PublicKey, Sig: sk.Sig, Revocations: sk.Revocations}}
		}
	}
	if enc.PublicKey == ent.PrimaryKey {
		min.Subkeys = nil // the primary key itself encrypts
	}
	var b bytes.Buffer
	if err := min.Serialize(&b); err != nil {
		return nil, false
	}
	return b.Bytes(), true
}

func (e *Engine) signingKey(addr string) *openpgp.Entity {
	now := time.Now()
	for _, ent := range e.private {
		if hasEmail(ent, addr) && !ent.Revoked(now) {
			if _, ok := ent.SigningKey(now); ok {
				return ent
			}
		}
	}
	return nil
}

// CanSign reports whether a private signing key exists for addr.
func (e *Engine) CanSign(addr string) bool { return e.signingKey(addr) != nil }

// IsEncrypted reports whether m is already PGP encrypted (PGP/MIME or inline).
func IsEncrypted(m *mimeutil.Message) bool {
	mt, params := m.Header.MediaType()
	if mt == "multipart/encrypted" && strings.EqualFold(params["protocol"], "application/pgp-encrypted") {
		return true
	}
	return bytes.Contains(m.Body, []byte("-----BEGIN PGP MESSAGE-----"))
}

// Encrypt encrypts the body entity of m to the keys in to and, if signer has
// a private key, signs it in the same pass (RFC 3156 section 6.2).
func (e *Engine) Encrypt(m *mimeutil.Message, to []*openpgp.Entity, signer string) ([]byte, error) {
	if len(to) == 0 {
		return nil, errors.New("pgp: no recipients")
	}
	var sign *openpgp.Entity
	if signer != "" {
		sign = e.signingKey(signer)
	}

	outer, entity := m.SplitEntity()

	var armored bytes.Buffer
	aw, err := armor.Encode(&armored, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	pw, err := openpgp.Encrypt(aw, to, sign, nil, nil)
	if err != nil {
		return nil, err
	}
	if _, err := pw.Write(entity); err != nil {
		return nil, err
	}
	if err := pw.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	armored.WriteString("\r\n")

	boundary := mimeutil.Boundary()
	var b bytes.Buffer
	fmt.Fprintf(&b, "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\r\n\tboundary=\"%s\"\r\n\r\n", boundary)
	b.WriteString("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n")
	fmt.Fprintf(&b, "--%s\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n", boundary)
	b.Write(mimeutil.CRLF(armored.Bytes()))
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return mimeutil.JoinEntity(outer, b.Bytes())
}

// SignatureStatus describes the result of verifying an embedded signature.
type SignatureStatus string

const (
	SigNone       SignatureStatus = "none"
	SigValid      SignatureStatus = "valid"
	SigInvalid    SignatureStatus = "invalid"
	SigUnknownKey SignatureStatus = "unknown-key"
)

// Result is the outcome of a successful decryption.
type Result struct {
	Message   []byte
	Signature SignatureStatus
	Signer    string // fingerprint of the signing key, when known
}

// ErrNotEncrypted is returned by Decrypt for messages that are not PGP/MIME.
var ErrNotEncrypted = errors.New("pgp: message is not PGP/MIME encrypted")

// Decrypt decrypts a PGP/MIME message and returns it with the decrypted
// entity in place of the encrypted body. Inline PGP is not handled.
func (e *Engine) Decrypt(m *mimeutil.Message) (*Result, error) {
	mt, params := m.Header.MediaType()
	if mt != "multipart/encrypted" || !strings.EqualFold(params["protocol"], "application/pgp-encrypted") {
		return nil, ErrNotEncrypted
	}
	start := bytes.Index(m.Body, []byte("-----BEGIN PGP MESSAGE-----"))
	end := bytes.Index(m.Body, []byte("-----END PGP MESSAGE-----"))
	if start < 0 || end < start {
		return nil, errors.New("pgp: no armored payload in multipart/encrypted")
	}
	block, err := armor.Decode(bytes.NewReader(m.Body[start : end+len("-----END PGP MESSAGE-----")]))
	if err != nil {
		return nil, err
	}

	// The keyring passed to ReadMessage is used both to find decryption keys
	// (only entities with private keys qualify) and to verify signatures.
	md, err := openpgp.ReadMessage(block.Body, keyring{e}, nil, nil)
	if err != nil {
		return nil, err
	}
	entity, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	res := &Result{Signature: SigNone}
	switch {
	case !md.IsSigned:
	case md.SignedBy == nil:
		res.Signature = SigUnknownKey
	case md.SignatureError != nil:
		res.Signature = SigInvalid
	default:
		res.Signature = SigValid
		res.Signer = fmt.Sprintf("%X", md.SignedBy.PublicKey.Fingerprint)
	}

	outer, _ := m.SplitEntity()
	res.Message, err = mimeutil.JoinEntity(outer, mimeutil.CRLF(entity))
	return res, err
}

// keyring routes signature lookups to public keys and decryption to private ones.
type keyring struct{ e *Engine }

func (k keyring) KeysById(id uint64) []openpgp.Key { return k.e.public.KeysById(id) }
func (k keyring) KeysByIdUsage(id uint64, usage byte) []openpgp.Key {
	return k.e.public.KeysByIdUsage(id, usage)
}
func (k keyring) DecryptionKeys() []openpgp.Key { return k.e.private.DecryptionKeys() }
