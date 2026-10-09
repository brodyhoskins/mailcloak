// Package filter is the runtime shared by mailcloak-encrypt and
// mailcloak-decrypt. Each is a Unix filter:
//
//	mailcloak-decrypt < in.eml > out.eml
//	mailcloak-encrypt -f alice@corp.example -- bob@example.org < msg.eml
//
// By default a filter reads one message from stdin and writes the result to
// stdout. The output can instead be handed to sendmail(1) or an SMTP server,
// which is how it runs as an MTA content filter, and with "listen" it runs as
// a daemon accepting LMTP/SMTP on a UNIX socket or TCP address.
package filter

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcloak/config"
	"github.com/brodyhoskins/mailcloak/internal/deliver"
	"github.com/brodyhoskins/mailcloak/internal/pipeline"
	"github.com/brodyhoskins/mailcloak/internal/server"
	"github.com/brodyhoskins/mailcloak/internal/version"
	"github.com/brodyhoskins/mailcloak/mimeutil"
)

// Exit statuses from sysexits.h, as interpreted by Postfix pipe(8).
const (
	ExitOK          = 0
	ExitUsage       = 64
	ExitUnavailable = 69 // permanent failure: the MTA bounces the message
	ExitTempFail    = 75 // temporary failure: the MTA defers and retries
)

// Builder constructs a filter's middleware from the loaded configuration.
type Builder func(cfg *config.Config, log *slog.Logger) (pipeline.Middleware, error)

// Run runs a filter and returns its exit status. which is "encrypt" or
// "decrypt": the config section the filter uses. args excludes the program
// name.
func Run(which string, build Builder, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	name := "mailcloak-" + which
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (default: $MAILCLOAK_CONFIG, $CONFIGURATION_DIRECTORY, XDG config dir, "+config.DefaultPath+")")
	verbose := fs.Bool("v", false, "log informational messages, including which config file was used")
	showVersion := fs.Bool("version", false, "print the version and exit")
	sender := fs.String("f", "", "envelope sender (default: the From header)")
	var o config.Overrides
	fs.StringVar(&o.PGPDir, "pgp", "", "PGP key directory")
	fs.StringVar(&o.SMIMEDir, "smime", "", "S/MIME certificate directory")
	fs.StringVar(&o.StateDir, "state", "", "state directory for discovered and harvested keys")
	fs.StringVar(&o.Output, "output", "", `where to write the result: "-" (stdout), "sendmail", "smtp:host:port", "smtp:unix:/path"`)
	fs.StringVar(&o.Listen, "listen", "", `run as a daemon on "unix:/path" or "host:port"`)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s [flags] [-f sender] [--] [recipient...] < message\n       %s [flags] -listen addr\n\nflags:\n", name, name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, name, version.String())
		return ExitOK
	}
	// "-f ''" is the null sender (bounces) and must not fall back to From.
	senderSet := false
	fs.Visit(func(f *flag.Flag) { senderSet = senderSet || f.Name == "f" })

	path, how := config.Locate(*cfgPath)

	// Configuration problems are temporary failures, so a broken deploy
	// defers mail instead of bouncing it.
	cfg, err := config.Load(path, which, o)
	if err != nil {
		fmt.Fprintf(stderr, "4.3.5 %s: %v\n", name, err)
		return ExitTempFail
	}
	fio := cfg.IO(which)
	daemon := fio.Listen != ""
	log, closeLog := openLog(name, cfg.Log, fio, daemon, *verbose, stderr)
	defer closeLog()
	if path == "" {
		log.Info("no config file, using flags and defaults")
	} else {
		log.Info("config loaded", "path", path, "found_by", how)
	}

	mw, err := build(cfg, log)
	if err != nil {
		log.Error("configuration error", "err", err)
		fmt.Fprintf(stderr, "4.3.5 %s: %v\n", name, err)
		return ExitTempFail
	}

	if daemon {
		if fs.NArg() > 0 || senderSet {
			fs.Usage()
			return ExitUsage
		}
		if err := runDaemon(name, cfg, fio, pipeline.Chain(output(cfg, fio), mw), log); err != nil {
			log.Error("daemon stopped", "err", err)
			return 1
		}
		return ExitOK
	}
	return runOnce(cfg, fio, mw, *sender, senderSet, fs.Args(), stdin, stdout, stderr, log)
}

// runOnce filters a single message from stdin.
func runOnce(cfg *config.Config, fio *config.IO, mw pipeline.Middleware, sender string, senderSet bool, rcpts []string, stdin io.Reader, stdout, stderr io.Writer, log *slog.Logger) int {
	data, err := io.ReadAll(io.LimitReader(stdin, cfg.MaxMessageBytes+1))
	if err != nil {
		return fail(stderr, log, fmt.Errorf("read message: %w", err))
	}
	if int64(len(data)) > cfg.MaxMessageBytes {
		return fail(stderr, log, &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too big for filter"})
	}

	env := &pipeline.Envelope{From: sender, To: rcpts, Data: data}
	fillFromHeaders(env, !senderSet, len(rcpts) == 0)
	noRcpts := &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "No recipients given or found in headers"}
	if len(env.To) == 0 && fio.Output != "-" {
		return fail(stderr, log, noRcpts)
	}

	var sink pipeline.Handler
	var collected *collector
	if fio.Output == "-" {
		collected = &collector{}
		sink = collected
	} else {
		sink = output(cfg, fio)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := pipeline.Chain(sink, mw).Handle(ctx, env); err != nil {
		return fail(stderr, log, err)
	}

	if collected != nil {
		// stdout holds exactly one message. If recipients needed different
		// treatments there is no single correct output.
		if len(collected.envs) == 0 {
			return fail(stderr, log, noRcpts)
		}
		if len(collected.envs) > 1 {
			return fail(stderr, log, &smtp.SMTPError{
				Code: 554, EnhancedCode: smtp.EnhancedCode{5, 3, 0},
				Message: "Recipients need different encryption methods; use -output sendmail/smtp or one recipient per run",
			})
		}
		if _, err := stdout.Write(collected.envs[0].Data); err != nil {
			return fail(stderr, log, err)
		}
	}
	return ExitOK
}

// collector is the stdout sink: it buffers results until the whole chain has
// succeeded, so a failure never leaves partial output.
type collector struct{ envs []*pipeline.Envelope }

func (c *collector) Handle(_ context.Context, env *pipeline.Envelope) error {
	c.envs = append(c.envs, env.Clone())
	return nil
}

// fillFromHeaders defaults the envelope sender to the From header and the
// recipients to To, Cc and Bcc, like sendmail -t.
func fillFromHeaders(env *pipeline.Envelope, sender, rcpts bool) {
	if !sender && !rcpts {
		return
	}
	m, err := mimeutil.Parse(env.Data)
	if err != nil {
		return
	}
	if sender {
		env.From = m.Header.FromAddress()
	}
	if rcpts {
		for _, h := range []string{"To", "Cc", "Bcc"} {
			list, err := mail.ParseAddressList(m.Header.Get(h))
			if err != nil {
				continue
			}
			for _, a := range list {
				env.To = append(env.To, a.Address)
			}
		}
	}
}

// fail logs err and maps it to an exit status. Under an MTA, stderr becomes
// the delivery status text (and possibly bounce text), so only SMTP-level
// reasons are printed, never internal details.
func fail(stderr io.Writer, log *slog.Logger, err error) int {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		// An expected outcome (e.g. strict-mode rejection) whose reason is
		// already reported on stderr.
		log.Info("message rejected", "err", err)
		fmt.Fprintf(stderr, "%d.%d.%d %s\n", se.EnhancedCode[0], se.EnhancedCode[1], se.EnhancedCode[2], se.Message)
		if se.Code >= 500 {
			return ExitUnavailable
		}
		return ExitTempFail
	}
	log.Error("message failed", "err", err)
	fmt.Fprintln(stderr, "4.3.0 Temporary filter failure")
	return ExitTempFail
}

func runDaemon(name string, cfg *config.Config, fio *config.IO, h pipeline.Handler, log *slog.Logger) error {
	mode, err := fio.SocketFileMode()
	if err != nil {
		return err
	}
	l, err := server.Listen(fio.Listen, mode)
	if err != nil {
		return err
	}
	srv := &server.Server{
		Name:            name,
		Domain:          cfg.Hostname,
		LMTP:            fio.Protocol == "lmtp",
		Handler:         h,
		MaxMessageBytes: cfg.MaxMessageBytes,
		Timeout:         cfg.Timeout,
		Log:             log,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// output returns the sink for a non-stdout output.
func output(cfg *config.Config, fio *config.IO) pipeline.Handler {
	if addr, ok := strings.CutPrefix(fio.Output, "smtp:"); ok {
		return &deliver.SMTP{Addr: addr, Helo: cfg.Hostname}
	}
	return &deliver.Sendmail{Path: cfg.Sendmail.Path, Args: cfg.Sendmail.Args}
}

// openLog picks the log destination. When a one-shot filter hands its output
// to the MTA it is running under pipe(8), where stderr is reserved for the
// status text, so logs default to syslog (mail facility). Interactive use
// logs warnings to stderr; daemons log everything to stderr.
func openLog(name, target string, fio *config.IO, daemon, verbose bool, stderr io.Writer) (*slog.Logger, func()) {
	level := slog.LevelInfo
	if target == "" {
		switch {
		case daemon:
			target = "stderr"
		case fio.Output != "-":
			target = "syslog"
		default:
			target = "stderr"
			if !verbose {
				level = slog.LevelWarn
			}
		}
	}
	var w io.Writer
	closer := func() {}
	switch target {
	case "none":
		w = io.Discard
	case "stderr":
		w = stderr
	case "syslog":
		sw, err := syslog.New(syslog.LOG_MAIL|syslog.LOG_INFO, name)
		if err != nil {
			w = io.Discard
			break
		}
		w, closer = sw, func() { sw.Close() }
	default:
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
		if err != nil {
			w = io.Discard
			break
		}
		w, closer = f, func() { f.Close() }
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("pid", os.Getpid()), closer
}
