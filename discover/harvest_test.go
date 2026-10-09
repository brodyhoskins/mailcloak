package discover

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcloak/internal/testkeys"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/smime"
)

func autocryptMsg(t *testing.T, from, date string, headers ...string) *mimeutil.Message {
	raw := "From: " + from + "\r\nDate: " + date + "\r\n"
	for _, h := range headers {
		raw += "Autocrypt: " + h + "\r\n"
	}
	m, err := mimeutil.Parse([]byte(raw + "Subject: hi\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const (
	day1 = "Mon, 05 Oct 2026 10:00:00 +0000"
	day2 = "Tue, 06 Oct 2026 10:00:00 +0000"
)

func TestAutocryptHarvestRules(t *testing.T) {
	now, _ := time.Parse(time.RFC1123Z, "Wed, 07 Oct 2026 10:00:00 +0000")
	st := &Store{Dir: t.TempDir()}
	h := &Harvester{Store: st, Autocrypt: true, Log: log, Now: func() time.Time { return now }}
	r := &Resolver{Store: st, Autocrypt: true, RequireMutual: true, Log: log, Now: h.Now}

	k1 := testkeys.PublicBytes(t, testkeys.NewPGP(t, "bob@example.org"))
	k2 := testkeys.PublicBytes(t, testkeys.NewPGP(t, "bob@example.org"))
	hdr := func(addr, prefer string, key []byte) string {
		return strings.ReplaceAll(FormatAutocrypt(addr, prefer, key), "\r\n", "")
	}
	key := func(addr string) []byte {
		var p autocryptPeer
		st.Get(kindAutocrypt, addr, &p)
		return p.Key
	}

	// Mismatched addr, and two headers at once, are both ignored.
	h.Harvest(autocryptMsg(t, "bob@example.org", day1, hdr("mallory@example.org", "mutual", k1)), nil)
	h.Harvest(autocryptMsg(t, "bob@example.org", day1, hdr("bob@example.org", "mutual", k1), hdr("bob@example.org", "mutual", k2)), nil)
	if key("bob@example.org") != nil {
		t.Fatal("invalid headers were harvested")
	}

	// A valid header is stored and usable.
	h.Harvest(autocryptMsg(t, "Bob <bob@example.org>", day2, hdr("bob@example.org", "mutual", k2)), nil)
	if k, _ := r.PGPKey(nil, "bob@example.org"); k == nil || k.Source != SourceAutocrypt {
		t.Fatalf("harvested key not used: %v", k)
	}

	// An older message doesn't replace a newer key.
	h.Harvest(autocryptMsg(t, "bob@example.org", day1, hdr("bob@example.org", "mutual", k1)), nil)
	if string(key("bob@example.org")) != string(k2) {
		t.Fatal("older header replaced newer key")
	}

	// Unknown critical attributes invalidate a header; "_" ones don't.
	if _, err := ParseAutocrypt("addr=a@b; keydata=AAAA; color=red"); err == nil {
		t.Error("unknown critical attribute accepted")
	}
	if _, err := ParseAutocrypt("addr=a@b; keydata=AAAA; _color=red"); err != nil {
		t.Errorf("non-critical attribute rejected: %v", err)
	}

	// nopreference keys aren't used while mutual is required.
	carol := testkeys.PublicBytes(t, testkeys.NewPGP(t, "carol@example.org"))
	h.Harvest(autocryptMsg(t, "carol@example.org", day2, hdr("carol@example.org", "nopreference", carol)), nil)
	if k, _ := r.PGPKey(nil, "carol@example.org"); k != nil {
		t.Error("nopreference key used despite RequireMutual")
	}

	// 36 days of mail without the header: the key goes stale.
	later := now.Add(36 * 24 * time.Hour)
	h.Now = func() time.Time { return later }
	h.Harvest(autocryptMsg(t, "bob@example.org", later.Format(time.RFC1123Z)), nil)
	if k, _ := r.PGPKey(nil, "bob@example.org"); k != nil {
		t.Error("stale Autocrypt key still used")
	}
}

func TestSMIMEHarvestRequiresTrustedChain(t *testing.T) {
	dir := t.TempDir()
	testkeys.SMIME(t, dir, "alice@corp.example", true)
	eng, err := smime.Load(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := mimeutil.Parse([]byte("From: alice@corp.example\r\nTo: dave@x\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nsigned body\r\n"))
	signed, err := eng.Sign(m, "alice@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	sm, _ := mimeutil.Parse(signed)

	// Untrusted root: not harvested.
	st := &Store{Dir: t.TempDir()}
	h := &Harvester{Store: st, SMIME: true, SMIMERoots: x509.NewCertPool(), Log: log}
	h.Harvest(sm, sm)
	r := &Resolver{Store: st, SMIMEHarvest: true, Log: log}
	if c, _ := r.SMIMECert(context.Background(), "alice@corp.example"); c != nil {
		t.Fatal("harvested a certificate that doesn't chain to a trusted root")
	}

	// Trusted root (the self-signed cert itself): harvested.
	pemBytes, _ := os.ReadFile(filepath.Join(dir, "alice@corp.example.crt"))
	blk, _ := pem.Decode(pemBytes)
	cert, _ := x509.ParseCertificate(blk.Bytes)
	h.SMIMERoots.AddCert(cert)
	h.Harvest(sm, sm)
	if c, _ := r.SMIMECert(context.Background(), "alice@corp.example"); c == nil || c.Source != SourceSMIMEHarvest {
		t.Fatalf("certificate not harvested: %v", c)
	}

	// Tampered content fails verification.
	st2 := &Store{Dir: t.TempDir()}
	tampered, _ := mimeutil.Parse([]byte(strings.Replace(string(signed), "signed body", "forged body", 1)))
	(&Harvester{Store: st2, SMIME: true, SMIMERoots: h.SMIMERoots, Log: log}).Harvest(tampered, tampered)
	if c, _ := (&Resolver{Store: st2, SMIMEHarvest: true, Log: log}).SMIMECert(context.Background(), "alice@corp.example"); c != nil {
		t.Fatal("harvested from a message with a broken signature")
	}
}
