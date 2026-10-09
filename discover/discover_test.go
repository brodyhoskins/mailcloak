package discover

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcloak/fetch"
	"github.com/brodyhoskins/mailcloak/internal/testkeys"
)

var log = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestWKDHashVector(t *testing.T) {
	// Example from draft-koch-openpgp-webkey-service.
	if got := WKDHash("Joe.Doe"); got != "iy9q119eutrkn8s1mk4r39qejnbu3n5q" {
		t.Fatalf("WKDHash = %s", got)
	}
	adv, direct, _ := WKDURLs("Joe.Doe@Example.ORG")
	if adv != "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" {
		t.Errorf("advanced URL: %s", adv)
	}
	if direct != "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" {
		t.Errorf("direct URL: %s", direct)
	}
}

// keyServer is an HTTPS server answering for any hostname. Keys are served
// with an ETag and revalidated with 304. blockAdvanced makes openpgpkey.*
// subdomains unreachable, as if they had no DNS record.
type keyServer struct {
	ts            *httptest.Server
	keys          map[string][]byte // URL path → key
	hits          atomic.Int32
	notModified   atomic.Int32
	blockAdvanced bool
	down          atomic.Bool
}

func newKeyServer(t *testing.T) *keyServer {
	ks := &keyServer{keys: map[string][]byte{}}
	ks.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.hits.Add(1)
		k, ok := ks.keys[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(k))
		if r.Header.Get("If-None-Match") == etag {
			ks.notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(k)
	}))
	t.Cleanup(ks.ts.Close)
	return ks
}

func (ks *keyServer) client() *fetch.Client {
	return &fetch.Client{HTTP: ks.httpClient(), MaxBody: maxKeyBytes}
}

const maxKeyBytes = 512 << 10

func (ks *keyServer) httpClient() *http.Client {
	tr := ks.ts.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tr.DisableKeepAlives = true // so "down" applies to every request
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ks.down.Load() {
			return nil, errors.New("connection refused")
		}
		if ks.blockAdvanced && strings.HasPrefix(addr, "openpgpkey.") {
			return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
		}
		return (&net.Dialer{}).DialContext(ctx, network, ks.ts.Listener.Addr().String())
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func TestWKDLookupCacheAndStale(t *testing.T) {
	ks := newKeyServer(t)
	bob := testkeys.NewPGP(t, "bob@example.org")
	ks.keys["/.well-known/openpgpkey/example.org/hu/"+WKDHash("bob")] = testkeys.PublicBytes(t, bob)

	now := time.Now()
	r := &Resolver{
		Store: &Store{Dir: t.TempDir()}, WKD: true, HTTP: ks.client(),
		CacheTTL: time.Hour, NegativeTTL: time.Minute, Log: log, Now: func() time.Time { return now },
	}
	ctx := context.Background()

	k, err := r.PGPKey(ctx, "bob@example.org")
	if err != nil || k == nil || k.Source != SourceWKD {
		t.Fatalf("want WKD key, got %v, %v", k, err)
	}
	if k, _ := r.PGPKey(ctx, "nobody@example.org"); k != nil {
		t.Fatal("found a key for an address with none published")
	}
	hits := ks.hits.Load()

	// Within the TTLs both answers come from the cache.
	r.PGPKey(ctx, "bob@example.org")
	r.PGPKey(ctx, "nobody@example.org")
	if ks.hits.Load() != hits {
		t.Error("cached lookups hit the network")
	}

	// After expiry the key is revalidated with a conditional request; the
	// 304 keeps it.
	now = now.Add(2 * time.Hour)
	if k, err := r.PGPKey(ctx, "bob@example.org"); k == nil || err != nil || ks.notModified.Load() != 1 {
		t.Fatalf("revalidation: key %v, err %v, 304s %d", k, err, ks.notModified.Load())
	}

	// After expiry with the source down: the known key is served stale, and
	// the unknown address reports an error rather than "no key".
	now = now.Add(2 * time.Hour)
	ks.down.Store(true)
	if k, err := r.PGPKey(ctx, "bob@example.org"); k == nil || err != nil {
		t.Errorf("stale key not served: %v, %v", k, err)
	}
	if k, err := r.PGPKey(ctx, "nobody@example.org"); k != nil || err == nil {
		t.Errorf("want lookup error for unknown address, got %v, %v", k, err)
	}
}

func TestWKDDirectFallbackAndUIDFilter(t *testing.T) {
	ks := newKeyServer(t)
	ks.blockAdvanced = true
	carol := testkeys.NewPGP(t, "carol@example.net")
	ks.keys["/.well-known/openpgpkey/hu/"+WKDHash("carol")] = testkeys.PublicBytes(t, carol)
	// A key published for dave whose only user ID is someone else's.
	ks.keys["/.well-known/openpgpkey/hu/"+WKDHash("dave")] = testkeys.PublicBytes(t, testkeys.NewPGP(t, "mallory@evil.example"))

	r := &Resolver{WKD: true, HTTP: ks.client(), Log: log}
	if k, err := r.PGPKey(context.Background(), "carol@example.net"); k == nil || err != nil {
		t.Fatalf("direct method: %v, %v", k, err)
	}
	if k, _ := r.PGPKey(context.Background(), "dave@example.net"); k != nil {
		t.Fatal("accepted a key without a matching user ID")
	}
}

func TestKeyserver(t *testing.T) {
	ks := newKeyServer(t)
	erin := testkeys.NewPGP(t, "erin@example.com")
	ks.keys["/vks/v1/by-email/erin@example.com"] = testkeys.PublicBytes(t, erin)
	r := &Resolver{Keyserver: "https://keys.example", HTTP: ks.client(), Log: log}
	k, err := r.PGPKey(context.Background(), "erin@example.com")
	if err != nil || k == nil || k.Source != SourceKeyserver {
		t.Fatalf("want keyserver key, got %v, %v", k, err)
	}
}
