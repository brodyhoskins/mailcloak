package fetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func client(ts *httptest.Server, max int64) *Client {
	tr := NewTransport((&net.Dialer{}).DialContext)
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &Client{HTTP: &http.Client{Transport: tr}, MaxBody: max}
}

func TestCompressionAndHTTP2(t *testing.T) {
	payload := bytes.Repeat([]byte("key material "), 100)
	var proto, acceptEnc string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto, acceptEnc = r.Proto, r.Header.Get("Accept-Encoding")
		var b bytes.Buffer
		switch r.URL.Path {
		case "/zstd":
			w.Header().Set("Content-Encoding", "zstd")
			zw, _ := zstd.NewWriter(&b)
			zw.Write(payload)
			zw.Close()
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			gw := gzip.NewWriter(&b)
			gw.Write(payload)
			gw.Close()
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			b.WriteString("whatever")
		}
		w.Write(b.Bytes())
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	c := client(ts, 1<<20)

	for _, enc := range []string{"zstd", "gzip"} {
		res, err := c.Get(context.Background(), ts.URL+"/"+enc, Validators{})
		if err != nil || !bytes.Equal(res.Body, payload) {
			t.Fatalf("%s: %v (body %d bytes)", enc, err, len(res.Body))
		}
	}
	if proto != "HTTP/2.0" {
		t.Errorf("want HTTP/2 with a custom dialer, got %s", proto)
	}
	if acceptEnc != "zstd, gzip" {
		t.Errorf("Accept-Encoding = %q", acceptEnc)
	}
	if _, err := c.Get(context.Background(), ts.URL+"/br", Validators{}); err == nil {
		t.Error("unrequested encoding accepted")
	}
}

func TestDecompressionBomb(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "zstd")
		zw, _ := zstd.NewWriter(w)
		zw.Write(make([]byte, 10<<20)) // 10 MiB of zeros: a few hundred bytes compressed
		zw.Close()
	}))
	defer ts.Close()
	if _, err := client(ts, 512<<10).Get(context.Background(), ts.URL, Validators{}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want size limit after decompression, got %v", err)
	}
}

func TestConditionalRequests(t *testing.T) {
	var ua string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.Header().Set("Cache-Control", "max-age=60")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 05 Oct 2026 10:00:00 GMT")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write([]byte("key"))
	}))
	defer ts.Close()
	c := client(ts, 1<<20)
	c.UserAgent = "mailcloak/1.2.3"

	res, err := c.Get(context.Background(), ts.URL, Validators{})
	if err != nil || res.Status != 200 || res.Validators.ETag != `"v1"` || res.MaxAge != time.Hour {
		t.Fatalf("first fetch: %+v, %v", res, err)
	}
	if ua != c.UserAgent {
		t.Errorf("User-Agent sent: %q", ua)
	}
	res, err = c.Get(context.Background(), ts.URL, res.Validators)
	if err != nil || res.Status != 304 || res.MaxAge != time.Minute || res.Validators.ETag != `"v1"` {
		t.Fatalf("revalidation: %+v, %v", res, err)
	}
}

func TestFreshness(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		cc, expires string
		want        time.Duration
		noStore     bool
	}{
		{"", "", -1, false},
		{"max-age=300", "", 5 * time.Minute, false},
		{"no-cache, max-age=300", "", 0, false},
		{"max-age=300, no-cache", "", 0, false},
		{"no-store", "", -1, true},
		{"", "Wed, 07 Oct 2026 13:00:00 GMT", time.Hour, false},
		{"", "0", 0, false},
		{"max-age=10", "Wed, 07 Oct 2026 13:00:00 GMT", 10 * time.Second, false}, // max-age beats Expires
	} {
		h := http.Header{}
		if tc.cc != "" {
			h.Set("Cache-Control", tc.cc)
		}
		if tc.expires != "" {
			h.Set("Expires", tc.expires)
		}
		got, noStore := freshness(h, now)
		if got != tc.want || noStore != tc.noStore {
			t.Errorf("Cache-Control %q Expires %q: got %v/%v, want %v/%v", tc.cc, tc.expires, got, noStore, tc.want, tc.noStore)
		}
	}
}
