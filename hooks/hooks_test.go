package hooks

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/smallstep/pkcs7"

	"github.com/brodyhoskins/mailcloak/discover"
	"github.com/brodyhoskins/mailcloak/internal/testkeys"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/pipeline"
	"github.com/brodyhoskins/mailcloak/smime"
)

const (
	alice = "alice@corp.example"  // our sender: PGP + S/MIME private keys
	bob   = "bob@pgp.example"     // external PGP recipient
	carol = "carol@smime.example" // external S/MIME recipient
	dave  = "dave@plain.example"  // no keys
)

var log = slog.New(slog.NewTextHandler(io.Discard, nil))

const plainMsg = "From: Alice <alice@corp.example>\r\n" +
	"To: bob@pgp.example, carol@smime.example, dave@plain.example\r\n" +
	"Subject: Quarterly numbers\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"The secret number is 42.\r\n"

// world holds two sets of engines: ours (alice's private keys, recipients'
// public keys) and theirs (recipients' private keys) for the reverse path.
type world struct {
	ourPGP     *pgp.Engine
	ourSMIME   *smime.Engine
	theirPGP   *pgp.Engine
	theirSMIME *smime.Engine
}

// ourKeys resolves recipients from our local directories only (no network).
func (w *world) ourKeys() *discover.Resolver {
	return &discover.Resolver{PGP: w.ourPGP, SMIME: w.ourSMIME, Log: log}
}

func newWorld(t *testing.T) *world {
	ourPGP, ourSMIME, theirPGP, theirSMIME := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	testkeys.PGP(t, ourPGP, alice, true)
	testkeys.SMIME(t, ourSMIME, alice, true)

	// Recipients: generate private keys on "their" side and copy the public
	// half to ours.
	testkeys.PGP(t, theirPGP, bob, true)
	testkeys.SMIME(t, theirSMIME, carol, true)
	copyPublic(t, theirPGP, ourPGP, bob+".asc")
	copyPublic(t, theirSMIME, ourSMIME, carol+".crt")
	// Let the receiving side verify alice's PGP signature.
	copyPublic(t, ourPGP, theirPGP, alice+".asc")

	w := &world{}
	var err error
	if w.ourPGP, err = pgp.Load(ourPGP, nil, log); err != nil {
		t.Fatal(err)
	}
	if w.ourSMIME, err = smime.Load(ourSMIME, log); err != nil {
		t.Fatal(err)
	}
	if w.theirPGP, err = pgp.Load(theirPGP, nil, log); err != nil {
		t.Fatal(err)
	}
	if w.theirSMIME, err = smime.Load(theirSMIME, log); err != nil {
		t.Fatal(err)
	}
	return w
}

// capture is a terminal handler recording every envelope by first recipient.
type capture map[string]*pipeline.Envelope

func (c capture) Handle(_ context.Context, env *pipeline.Envelope) error {
	for _, r := range env.To {
		c[r] = env.Clone()
	}
	return nil
}

func TestEncryptThenDecrypt(t *testing.T) {
	w := newWorld(t)
	out := capture{}
	h := pipeline.Chain(out, (&Encrypt{
		PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: w.ourKeys(), Prefer: []string{MethodPGP, MethodSMIME}, Mode: Opportunistic, Log: log,
	}).Middleware)

	err := h.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{bob, carol, dave}, Data: []byte(plainMsg)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 deliveries, got %d", len(out))
	}
	for r, env := range out {
		if len(env.To) != 1 {
			t.Errorf("%s: recipients leaked across groups: %v", r, env.To)
		}
		if !bytes.Contains(env.Data, []byte("Subject: Quarterly numbers")) {
			t.Errorf("%s: transport headers not preserved", r)
		}
		if r != dave && bytes.Contains(env.Data, []byte("secret number")) {
			t.Errorf("%s: plaintext leaked", r)
		}
	}

	// dave: plaintext + valid detached S/MIME signature.
	verifySMIMESignature(t, out[dave].Data)

	// bob: PGP/MIME, decryptable on his side, signed by alice.
	in := &Decrypt{PGP: w.theirPGP, SMIME: w.theirSMIME, Log: log}
	got := runDecrypt(t, in, out[bob])
	if !strings.Contains(got, "The secret number is 42.") {
		t.Errorf("bob: decrypted body missing:\n%s", got)
	}
	if !strings.Contains(got, HeaderSignature+": pgp; status=valid") {
		t.Errorf("bob: expected valid PGP signature header:\n%s", got)
	}
	if strings.Contains(got, "pkcs7-signature") {
		t.Error("bob: PGP mail must not carry an S/MIME signature")
	}

	// carol: S/MIME enveloped, decrypts to an S/MIME-signed entity.
	got = runDecrypt(t, in, out[carol])
	if !strings.Contains(got, "The secret number is 42.") {
		t.Errorf("carol: decrypted body missing:\n%s", got)
	}
	verifySMIMESignature(t, []byte(got))
}

func TestStrictRejectsUnencryptable(t *testing.T) {
	w := newWorld(t)
	out := capture{}
	h := pipeline.Chain(out, (&Encrypt{
		PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: w.ourKeys(), Prefer: []string{MethodPGP, MethodSMIME}, Mode: Strict, StrictSources: []discover.Source{discover.SourceLocal}, Log: log,
	}).Middleware)

	err := h.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{bob, dave}, Data: []byte(plainMsg)})
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 || !strings.Contains(se.Message, dave) {
		t.Fatalf("want 550 naming dave, got %v", err)
	}
	if len(out) != 0 {
		t.Fatal("strict mode must not deliver any part of a rejected message")
	}

	if err := h.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{bob, carol}, Data: []byte(plainMsg)}); err != nil {
		t.Fatalf("fully encryptable message rejected: %v", err)
	}
}

func TestEncryptSkipsLocalDomains(t *testing.T) {
	w := newWorld(t)
	out := capture{}
	h := pipeline.Chain(out, (&Encrypt{
		PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: w.ourKeys(), Prefer: []string{MethodPGP, MethodSMIME}, Mode: Strict,
		StrictSources: []discover.Source{discover.SourceLocal}, LocalDomains: []string{"PGP.example"}, Log: log,
	}).Middleware)
	// bob has a PGP key, but his domain is local: no encryption, and strict
	// mode doesn't object.
	if err := h.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{bob}, Data: []byte(plainMsg)}); err != nil {
		t.Fatal(err)
	}
	if string(out[bob].Data) != plainMsg {
		t.Errorf("local recipient's mail was modified:\n%s", out[bob].Data)
	}
}

func TestEncryptPassesThroughClientEncrypted(t *testing.T) {
	w := newWorld(t)
	head := "From: alice@corp.example\r\nTo: dave@plain.example\r\n"
	for name, msg := range map[string]string{
		"smime":      head + "Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nAAAA\r\n",
		"pgp/mime":   head + "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=b\r\n\r\n--b\r\n\r\nVersion: 1\r\n--b--\r\n",
		"inline pgp": head + "Content-Type: text/plain\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n\r\nAAAA\r\n-----END PGP MESSAGE-----\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			out := capture{}
			// Strict mode, and dave has no key: only passthrough lets it out.
			h := pipeline.Chain(out, (&Encrypt{PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: w.ourKeys(), Prefer: []string{MethodPGP, MethodSMIME}, Mode: Strict, Log: log}).Middleware)
			if err := h.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{dave}, Data: []byte(msg)}); err != nil {
				t.Fatal(err)
			}
			if string(out[dave].Data) != msg {
				t.Errorf("already-encrypted message was modified:\n%s", out[dave].Data)
			}
		})
	}
}

func TestDecryptStripsSpoofedHeaders(t *testing.T) {
	msg := "From: x@evil.example\r\nX-Mailcloak-Signature: pgp; status=valid\r\nSubject: hi\r\n\r\nbody\r\n"
	out := capture{}
	h := pipeline.Chain(out, (&Decrypt{Log: log}).Middleware)
	if err := h.Handle(context.Background(), &pipeline.Envelope{From: "x@evil.example", To: []string{alice}, Data: []byte(msg)}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out[alice].Data, []byte("X-Mailcloak")) {
		t.Error("spoofed X-Mailcloak header survived")
	}
}

func TestEncryptToSelf(t *testing.T) {
	w := newWorld(t)
	ours := &Decrypt{PGP: w.ourPGP, SMIME: w.ourSMIME, Log: log}
	for _, self := range []bool{false, true} {
		out := capture{}
		h := pipeline.Chain(out, (&Encrypt{
			PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: w.ourKeys(), Prefer: []string{MethodPGP, MethodSMIME}, Mode: Opportunistic, EncryptToSelf: self, Log: log,
		}).Middleware)
		if err := h.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{bob, carol}, Data: []byte(plainMsg)}); err != nil {
			t.Fatal(err)
		}
		// The provider's Sent copy is one of these: the sender must be able
		// to read it exactly when encrypt_to_self is on.
		for _, r := range []string{bob, carol} {
			got := runDecrypt(t, ours, out[r])
			if readable := strings.Contains(got, "The secret number is 42."); readable != self {
				t.Errorf("encrypt_to_self=%v: sender can read copy for %s: %v", self, r, readable)
			}
		}
	}
}

func runDecrypt(t *testing.T, in *Decrypt, env *pipeline.Envelope) string {
	t.Helper()
	out := capture{}
	if err := pipeline.Chain(out, in.Middleware).Handle(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	return string(out[env.To[0]].Data)
}

func verifySMIMESignature(t *testing.T, raw []byte) {
	t.Helper()
	m, err := mimeutil.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	mt, params := m.Header.MediaType()
	if mt != "multipart/signed" || params["protocol"] != "application/pkcs7-signature" {
		t.Fatalf("not S/MIME signed: %s", mt)
	}
	// The signed bytes are exactly those between the first boundary line and
	// the CRLF preceding the second.
	delim := []byte("--" + params["boundary"] + "\r\n")
	parts := bytes.Split(m.Body, delim)
	if len(parts) < 3 {
		t.Fatalf("malformed multipart/signed")
	}
	signed := bytes.TrimSuffix(parts[1], []byte("\r\n"))

	mr := multipart.NewReader(bytes.NewReader(m.Body), params["boundary"])
	if _, err := mr.NextPart(); err != nil {
		t.Fatal(err)
	}
	sigPart, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if ct, _, _ := mime.ParseMediaType(sigPart.Header.Get("Content-Type")); ct != "application/pkcs7-signature" {
		t.Fatalf("second part is %s", ct)
	}
	b64, _ := io.ReadAll(sigPart)
	der, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(b64), nil)))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	p7.Content = signed
	if err := p7.Verify(); err != nil {
		t.Fatalf("S/MIME signature invalid: %v", err)
	}
	if !bytes.Contains(signed, []byte("The secret number is 42.")) {
		t.Error("signed content missing body")
	}
}
