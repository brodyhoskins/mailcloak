package hooks

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcloak/discover"
	"github.com/brodyhoskins/mailcloak/fetch"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/pipeline"
)

// TestAutocryptRoundTrip: our encrypt filter advertises alice's key, the
// other side's decrypt filter harvests it, and their encrypt filter then
// encrypts back to alice with it.
func TestAutocryptRoundTrip(t *testing.T) {
	w := newWorld(t)
	out := capture{}
	ours := pipeline.Chain(out, (&Encrypt{
		PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: w.ourKeys(), Prefer: []string{MethodPGP},
		Mode: Opportunistic, AdvertiseAutocrypt: true, PreferEncrypt: "mutual", Log: log,
	}).Middleware)
	if err := ours.Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{dave}, Data: []byte(plainMsg)}); err != nil {
		t.Fatal(err)
	}
	sent, _ := mimeutil.Parse(out[dave].Data)
	ac, err := discover.ParseAutocrypt(sent.Header.Get("Autocrypt"))
	if err != nil || ac.Addr != alice || ac.PreferEncrypt != "mutual" {
		t.Fatalf("bad Autocrypt header: %v, %+v", err, ac)
	}
	keys, _ := pgp.ParseKeys(ac.KeyData)
	if len(keys) != 1 || len(keys[0].Identities) != 1 || keys[0].PrivateKey != nil {
		t.Fatalf("advertised key is not minimal/public: %d entities", len(keys))
	}
	// The S/MIME signature on the plain message must survive the added header.
	verifySMIMESignature(t, out[dave].Data)

	// Their side: decrypt filter with harvesting, sharing a store with their
	// encrypt filter.
	store := &discover.Store{Dir: t.TempDir()}
	theirDecrypt := pipeline.Chain(capture{}, (&Decrypt{
		Harvest: &discover.Harvester{Store: store, Autocrypt: true, Log: log}, Log: log,
	}).Middleware)
	if err := theirDecrypt.Handle(context.Background(), out[dave]); err != nil {
		t.Fatal(err)
	}

	reply := "From: dave@plain.example\r\nTo: alice@corp.example\r\nSubject: re\r\n\r\nreply secret\r\n"
	back := capture{}
	theirs := pipeline.Chain(back, (&Encrypt{
		PGP: w.theirPGP, Keys: &discover.Resolver{PGP: w.theirPGP, Store: store, Autocrypt: true, RequireMutual: true, Log: log},
		Prefer: []string{MethodPGP}, Mode: Opportunistic, Log: log,
	}).Middleware)
	if err := theirs.Handle(context.Background(), &pipeline.Envelope{From: dave, To: []string{alice}, Data: []byte(reply)}); err != nil {
		t.Fatal(err)
	}
	if got := string(back[alice].Data); !strings.Contains(got, "multipart/encrypted") || strings.Contains(got, "reply secret") {
		t.Fatalf("reply not encrypted with harvested key:\n%s", got)
	}

	// And alice's side can decrypt it.
	if got := runDecrypt(t, &Decrypt{PGP: w.ourPGP, Log: log}, back[alice]); !strings.Contains(got, "reply secret") {
		t.Fatalf("alice can't decrypt the reply:\n%s", got)
	}
}

func TestStrictSources(t *testing.T) {
	w := newWorld(t)

	// bob's side advertises his key; we harvest it into a store, so our
	// resolver knows bob only through Autocrypt.
	tap := capture{}
	err := pipeline.Chain(tap, (&Encrypt{
		PGP: w.theirPGP, Keys: &discover.Resolver{PGP: w.theirPGP, Log: log}, Prefer: []string{MethodPGP},
		AdvertiseAutocrypt: true, PreferEncrypt: "mutual", Log: log,
	}).Middleware).Handle(context.Background(), &pipeline.Envelope{
		From: bob, To: []string{alice}, Data: []byte("From: bob@pgp.example\r\nTo: alice@corp.example\r\n\r\nhi\r\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &discover.Store{Dir: t.TempDir()}
	m, _ := mimeutil.Parse(tap[alice].Data)
	(&discover.Harvester{Store: store, Autocrypt: true, Log: log}).Harvest(m, m)

	keys := &discover.Resolver{Store: store, Autocrypt: true, RequireMutual: true, Log: log}
	encrypt := func(sources ...discover.Source) (capture, error) {
		out := capture{}
		err := pipeline.Chain(out, (&Encrypt{
			PGP: w.ourPGP, Keys: keys, Prefer: []string{MethodPGP}, Mode: Strict, StrictSources: sources, Log: log,
		}).Middleware).Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{bob}, Data: []byte(plainMsg)})
		return out, err
	}

	var se *smtp.SMTPError
	if _, err := encrypt(discover.SourceLocal, discover.SourceWKD); !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("Autocrypt key satisfied strict mode without being trusted: %v", err)
	}
	out, err := encrypt(discover.SourceLocal, discover.SourceAutocrypt)
	if err != nil || !strings.Contains(string(out[bob].Data), "multipart/encrypted") {
		t.Fatalf("trusted Autocrypt key not used: %v", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network unreachable")
}

func TestStrictDefersOnLookupFailure(t *testing.T) {
	w := newWorld(t)
	keys := &discover.Resolver{PGP: w.ourPGP, WKD: true, HTTP: &fetch.Client{HTTP: &http.Client{Transport: failingTransport{}}, MaxBody: 1 << 20}, Log: log}
	run := func(mode Mode) error {
		return pipeline.Chain(capture{}, (&Encrypt{
			PGP: w.ourPGP, SMIME: w.ourSMIME, Keys: keys, Prefer: []string{MethodPGP}, Mode: mode,
			StrictSources: []discover.Source{discover.SourceLocal, discover.SourceWKD}, Log: log,
		}).Middleware).Handle(context.Background(), &pipeline.Envelope{From: alice, To: []string{dave}, Data: []byte(plainMsg)})
	}
	var se *smtp.SMTPError
	if err := run(Strict); !errors.As(err, &se) || se.Code != 451 {
		t.Fatalf("strict: want 451 defer on lookup failure, got %v", err)
	}
	if err := run(Opportunistic); err != nil {
		t.Fatalf("opportunistic: lookup failure should fall back to signed, got %v", err)
	}
}
