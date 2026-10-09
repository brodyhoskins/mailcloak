package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcloak/internal/deliver"
	"github.com/brodyhoskins/mailcloak/pipeline"
)

var log = slog.New(slog.NewTextHandler(io.Discard, nil))

// sink is an upstream SMTP server (standing in for the MTA's reinjection
// port) that records what it receives.
type sink struct{ got chan pipeline.Envelope }

func (s *sink) NewSession(*smtp.Conn) (smtp.Session, error) { return &sinkSession{s: s}, nil }

type sinkSession struct {
	s   *sink
	env pipeline.Envelope
}

func (ss *sinkSession) Reset()        {}
func (ss *sinkSession) Logout() error { return nil }
func (ss *sinkSession) Mail(f string, _ *smtp.MailOptions) error {
	ss.env.From = f
	return nil
}
func (ss *sinkSession) Rcpt(r string, _ *smtp.RcptOptions) error {
	if strings.HasPrefix(r, "nobody@") {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	ss.env.To = append(ss.env.To, r)
	return nil
}
func (ss *sinkSession) Data(r io.Reader) error {
	ss.env.Data, _ = io.ReadAll(r)
	ss.s.got <- ss.env
	return nil
}

// sockDir returns a short temporary directory: UNIX socket paths are limited
// to ~104 bytes and t.TempDir() paths can exceed that on macOS.
func sockDir(t *testing.T) string {
	d, err := os.MkdirTemp("", "mc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// startSink runs the upstream on a UNIX socket and returns its "unix:" address.
func startSink(t *testing.T) (*sink, string) {
	up := &sink{got: make(chan pipeline.Envelope, 1)}
	addr := "unix:" + filepath.Join(sockDir(t), "reinject.sock")
	l, err := Listen(addr, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(up)
	srv.Domain = "mta"
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return up, addr
}

func startFilter(t *testing.T, addr string, lmtp bool, h pipeline.Handler) {
	l, err := Listen(addr, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Name: "test", Domain: "filter", LMTP: lmtp, Handler: h, Timeout: 5 * time.Second, Log: log}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
}

var tag = func(next pipeline.Handler) pipeline.Handler {
	return pipeline.HandlerFunc(func(ctx context.Context, env *pipeline.Envelope) error {
		env.Data = append([]byte("X-Tagged: yes\r\n"), env.Data...)
		return next.Handle(ctx, env)
	})
}

const msg = "From: a@x\r\nTo: b@y\r\nSubject: t\r\n\r\nhello\r\n"

func TestLMTPOnUnixSocket(t *testing.T) {
	up, upAddr := startSink(t)
	addr := "unix:" + filepath.Join(sockDir(t), "filter.sock")
	startFilter(t, addr, true, pipeline.Chain(&deliver.SMTP{Addr: upAddr, Helo: "filter"}, tag))

	_, path := SplitAddr(addr)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c := smtp.NewClientLMTP(conn)
	defer c.Close()
	if err := c.Hello("mta"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("a@x", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("b@y", nil); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, msg)
	if _, err := w.CloseWithLMTPResponse(); err != nil {
		t.Fatal(err)
	}

	select {
	case env := <-up.got:
		if env.From != "a@x" || len(env.To) != 1 || env.To[0] != "b@y" {
			t.Errorf("envelope mangled: %+v", env)
		}
		if !bytes.HasPrefix(env.Data, []byte("X-Tagged: yes\r\n")) {
			t.Errorf("middleware didn't run: %q", env.Data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reinjection never arrived")
	}
}

func TestSMTPOnTCPPropagatesRejection(t *testing.T) {
	up, upAddr := startSink(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	startFilter(t, addr, false, pipeline.Chain(&deliver.SMTP{Addr: upAddr, Helo: "filter"}, tag))

	if err := send(addr, "a@x", []string{"b@y"}); err != nil {
		t.Fatal(err)
	}
	<-up.got

	// A permanent rejection on reinjection must reach the MTA as a 5xx.
	err := send(addr, "a@x", []string{"nobody@y"})
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("want 550 propagated, got %v", err)
	}
}

func send(addr, from string, to []string) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	io.WriteString(w, msg)
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
