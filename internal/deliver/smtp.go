// Package deliver contains the terminal handlers that hand a processed
// message to the next hop.
package deliver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcloak/pipeline"
)

// TLS modes for upstream connections.
const (
	TLSNone     = "none"
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"
)

// SMTP relays envelopes to an SMTP server, e.g. a Postfix smtpd set up to
// receive filtered mail.
type SMTP struct {
	Addr      string // "host:port" or "unix:/path"
	Helo      string
	TLS       string // TLSNone, TLSStartTLS or TLSImplicit
	TLSConfig *tls.Config
	Timeout   time.Duration
}

func (f *SMTP) Handle(ctx context.Context, env *pipeline.Envelope) error {
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	network, address := "tcp", f.Addr
	if p, ok := strings.CutPrefix(f.Addr, "unix:"); ok {
		network, address = "unix", p
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return fmt.Errorf("deliver smtp: dial %s: %w", f.Addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	tlsCfg := f.TLSConfig
	if tlsCfg == nil {
		host, _, _ := net.SplitHostPort(f.Addr)
		tlsCfg = &tls.Config{ServerName: host}
	}

	var c *smtp.Client
	switch f.TLS {
	case TLSImplicit:
		c = smtp.NewClient(tls.Client(conn, tlsCfg))
	case TLSStartTLS:
		if c, err = smtp.NewClientStartTLS(conn, tlsCfg); err != nil {
			conn.Close()
			return fmt.Errorf("deliver smtp: starttls: %w", err)
		}
	default:
		c = smtp.NewClient(conn)
	}
	defer c.Close()

	if f.Helo != "" {
		if err := c.Hello(f.Helo); err != nil {
			return err
		}
	}
	// Errors from the client are *smtp.SMTPError when upstream replied, so
	// permanent upstream rejections propagate to our client unchanged.
	if err := c.Mail(env.From, nil); err != nil {
		return err
	}
	for _, r := range env.To {
		if err := c.Rcpt(r, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(env.Data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
