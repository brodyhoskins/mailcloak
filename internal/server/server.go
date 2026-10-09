// Package server is the daemon-mode front end of a filter: an SMTP or LMTP
// listener on a TCP address or UNIX socket that hands each received envelope
// to a pipeline.Handler.
package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcloak/internal/pipeline"
)

// Server is a filter listener.
type Server struct {
	Name            string // filter name, for logs
	Domain          string // greeting hostname
	LMTP            bool
	Handler         pipeline.Handler
	MaxMessageBytes int64
	Timeout         time.Duration // per-message handler deadline
	Log             *slog.Logger

	srv *smtp.Server
}

// SplitAddr parses "unix:/path" or "host:port" into a network and address.
func SplitAddr(addr string) (network, address string) {
	if p, ok := strings.CutPrefix(addr, "unix:"); ok {
		return "unix", p
	}
	return "tcp", addr
}

// Listen opens addr. A stale UNIX socket at the same path is removed first and
// the new one is given mode.
func Listen(addr string, mode fs.FileMode) (net.Listener, error) {
	network, address := SplitAddr(addr)
	if network == "unix" {
		if fi, err := os.Lstat(address); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			_ = os.Remove(address)
		}
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.Chmod(address, mode); err != nil {
			l.Close()
			return nil, fmt.Errorf("chmod %s: %w", address, err)
		}
	}
	return l, nil
}

// Serve accepts connections on l until Shutdown.
func (s *Server) Serve(l net.Listener) error {
	srv := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		return &session{s: s}, nil
	}))
	srv.Domain = s.Domain
	srv.LMTP = s.LMTP
	srv.MaxMessageBytes = s.MaxMessageBytes
	srv.MaxRecipients = 0 // the MTA already enforced its limits
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = 5 * time.Minute
	s.srv = srv

	proto := "smtp"
	if s.LMTP {
		proto = "lmtp"
	}
	s.Log.Info("listening", "filter", s.Name, "addr", l.Addr().String(), "protocol", proto)
	err := srv.Serve(l)
	if errors.Is(err, smtp.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting connections and waits for sessions to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

type session struct {
	s   *Server
	env pipeline.Envelope
}

func (ss *session) Reset()        { ss.env = pipeline.Envelope{} }
func (ss *session) Logout() error { return nil }

func (ss *session) Mail(from string, _ *smtp.MailOptions) error {
	ss.env = pipeline.Envelope{From: from}
	return nil
}

func (ss *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	ss.env.To = append(ss.env.To, to)
	return nil
}

// Data runs the handler. Under LMTP the same status is reported for every
// recipient, since a filter accepts or defers the message as a whole.
func (ss *session) Data(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return err
	}
	env := ss.env
	env.Data = buf.Bytes()

	ctx := context.Background()
	if ss.s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ss.s.Timeout)
		defer cancel()
	}
	err := ss.s.Handler.Handle(ctx, &env)
	if err == nil {
		return nil
	}
	ss.s.Log.Error("message failed", "filter", ss.s.Name, "from", env.From, "err", err)
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr
	}
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary filter failure"}
}
