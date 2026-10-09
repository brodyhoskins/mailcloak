// Package fetch is a small HTTP client for key lookups. It speaks HTTP/2,
// asks for zstd or gzip compression, revalidates cached responses
// with conditional requests, and reports how long a response may be cached.
package fetch

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Validators identify a cached response for revalidation.
type Validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// Result is the outcome of a GET.
type Result struct {
	Status     int // 200, 304 (cached copy still valid) or 404
	Body       []byte
	Validators Validators
	// MaxAge is how long the response may be used without revalidation, from
	// Cache-Control or Expires; -1 if the server didn't say.
	MaxAge  time.Duration
	NoStore bool // Cache-Control: no-store
}

// Client fetches small documents.
type Client struct {
	HTTP      *http.Client
	MaxBody   int64 // limit on the decoded body
	UserAgent string
}

// NewTransport returns an HTTP/2-capable transport that dials with dial.
func NewTransport(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext: dial,
		// Go only negotiates HTTP/2 on its own when the transport is not
		// customised; with a custom dialer it has to be asked for.
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		// We set Accept-Encoding ourselves to add zstd, so the
		// transport must not also add gzip and decode it transparently.
		DisableCompression: true,
	}
}

// ErrStatus is returned for responses other than 200, 304 and 404.
type ErrStatus int

func (e ErrStatus) Error() string { return fmt.Sprintf("http status %d", int(e)) }

// Get fetches url. If prev is non-empty the request is conditional and a 304
// means the caller's copy is still valid.
func (c *Client) Get(ctx context.Context, url string, prev Validators) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "zstd, gzip")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	res := &Result{Status: resp.StatusCode, MaxAge: -1}
	res.MaxAge, res.NoStore = freshness(resp.Header, time.Now())
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		res.Validators = prev
		return res, nil
	case http.StatusNotFound:
		return res, nil
	default:
		return nil, ErrStatus(resp.StatusCode)
	}

	res.Validators = Validators{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	body, err := decode(resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	// The limit applies after decompression, so a small compressed response
	// can't expand without bound.
	res.Body, err = io.ReadAll(io.LimitReader(body, c.MaxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(res.Body)) > c.MaxBody {
		return nil, errors.New("fetch: response too large")
	}
	return res, nil
}

func decode(resp *http.Response) (io.ReadCloser, error) {
	switch enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
		return io.NopCloser(resp.Body), nil
	case "zstd":
		d, err := zstd.NewReader(resp.Body, zstd.WithDecoderMaxMemory(64<<20), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case "gzip":
		return gzip.NewReader(resp.Body)
	default:
		return nil, fmt.Errorf("fetch: unsupported Content-Encoding %q", enc)
	}
}

// freshness reads Cache-Control and Expires (RFC 9111). It returns -1 if
// neither gives a lifetime.
func freshness(h http.Header, now time.Time) (maxAge time.Duration, noStore bool) {
	maxAge = -1
	for _, d := range strings.Split(h.Get("Cache-Control"), ",") {
		k, v, _ := strings.Cut(strings.ToLower(strings.TrimSpace(d)), "=")
		switch k {
		case "no-store":
			noStore = true
		case "no-cache":
			maxAge = 0
		case "max-age":
			if maxAge != 0 { // no-cache wins
				if n, err := strconv.Atoi(strings.Trim(v, `"`)); err == nil && n >= 0 {
					maxAge = time.Duration(n) * time.Second
				}
			}
		}
	}
	if maxAge < 0 {
		if e, err := http.ParseTime(h.Get("Expires")); err == nil {
			maxAge = max(e.Sub(now), 0)
		} else if h.Get("Expires") != "" {
			maxAge = 0 // invalid Expires means already expired
		}
	}
	return maxAge, noStore
}
