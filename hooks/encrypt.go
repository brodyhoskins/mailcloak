// Package hooks contains the crypto middlewares used by the filters.
package hooks

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcloak/discover"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/pipeline"
	"github.com/brodyhoskins/mailcloak/smime"
)

// Mode controls what happens to mail that cannot be encrypted.
type Mode string

const (
	// Opportunistic encrypts where a key is available and otherwise sends
	// S/MIME-signed (or plain) mail.
	Opportunistic Mode = "opportunistic"
	// Strict rejects any message that cannot be encrypted to every recipient.
	Strict Mode = "strict"
)

// Method names, also used in the "prefer" configuration list.
const (
	MethodPGP   = "pgp"
	MethodSMIME = "smime"
	methodPlain = "plain"
	methodLocal = "local"
)

// Encrypt signs and encrypts mail leaving the organisation.
//
//   - PGP recipients get PGP/MIME, signed with the sender's PGP key if present.
//   - S/MIME recipients get sign-then-encrypt with the sender's S/MIME key.
//   - Everyone else gets an S/MIME signature (opportunistic mode only).
//   - Recipients in LocalDomains are passed through untouched.
//
// Recipients are grouped by method and each group is passed to next as its own
// envelope, since a single message body cannot serve all of them.
type Encrypt struct {
	PGP          *pgp.Engine   // signing; nil disables PGP
	SMIME        *smime.Engine // signing; nil disables S/MIME
	Keys         *discover.Resolver
	Prefer       []string // method order when a recipient has both kinds of key
	Mode         Mode
	LocalDomains []string
	// StrictSources limits which key sources count in strict mode, e.g. so a
	// trust-on-first-use Autocrypt key can't satisfy "encrypted only".
	StrictSources []discover.Source
	// AdvertiseAutocrypt adds an Autocrypt header with the sender's PGP key.
	AdvertiseAutocrypt bool
	PreferEncrypt      string // "mutual" or "nopreference", for the header
	// EncryptToSelf also encrypts to the sender's own key, so the copy a
	// provider saves to Sent stays readable to the sender.
	EncryptToSelf bool
	Log           *slog.Logger
}

// group is the recipients that share one treatment.
type group struct {
	rcpts []string
	pgp   []*openpgp.Entity
	certs []*x509.Certificate
}

func (o *Encrypt) Middleware(next pipeline.Handler) pipeline.Handler {
	return pipeline.HandlerFunc(func(ctx context.Context, env *pipeline.Envelope) error {
		return o.handle(ctx, env, next)
	})
}

func (o *Encrypt) handle(ctx context.Context, env *pipeline.Envelope, next pipeline.Handler) error {
	m, err := mimeutil.Parse(env.Data)
	if err != nil {
		return permanent("message could not be parsed: %v", err)
	}

	// The client already encrypted end-to-end: leave it alone.
	if pgp.IsEncrypted(m) || smime.IsEncrypted(m) {
		o.Log.Info("encrypt: already encrypted, passing through", "from", env.From, "rcpts", len(env.To))
		return next.Handle(ctx, &pipeline.Envelope{From: env.From, To: env.To, Data: m.Bytes()})
	}

	sender := m.Header.FromAddress()
	if sender == "" {
		sender = strings.ToLower(env.From)
	}
	o.advertise(m, sender)
	// Don't stack a second signature on a message the client signed itself.
	alreadySigned := smime.IsSigned(m)

	groups := map[string]*group{}
	var noKey, unknown []string
	for _, r := range env.To {
		method, pk, cert, err := o.methodFor(ctx, r)
		if err != nil {
			unknown = append(unknown, r)
		}
		if method == methodPlain && err == nil {
			noKey = append(noKey, r)
		}
		g := groups[method]
		if g == nil {
			g = &group{}
			groups[method] = g
		}
		g.rcpts = append(g.rcpts, r)
		if pk != nil {
			g.pgp = append(g.pgp, pk)
		}
		if cert != nil {
			g.certs = append(g.certs, cert)
		}
	}

	if o.Mode == Strict {
		// A failed lookup might have found a key: defer rather than bounce.
		if len(unknown) > 0 {
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 3}, Message: "Key lookup failed for: " + strings.Join(unknown, ", ")}
		}
		if len(noKey) > 0 {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Encryption required but no key for: " + strings.Join(noKey, ", ")}
		}
	}

	// Each group becomes its own transaction. If a later group fails after an
	// earlier one was accepted, the MTA retries and the earlier recipients
	// may receive a duplicate.
	for _, method := range []string{methodLocal, MethodPGP, MethodSMIME, methodPlain} {
		g := groups[method]
		if g == nil {
			continue
		}
		data, err := o.transform(method, m, g, sender, alreadySigned)
		if err != nil {
			o.Log.Error("encrypt: crypto failed", "method", method, "from", sender, "err", err)
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Encryption failed"}
		}
		o.Log.Info("encrypt: relaying", "method", method, "from", sender, "rcpts", len(g.rcpts))
		if err := next.Handle(ctx, &pipeline.Envelope{From: env.From, To: g.rcpts, Data: data}); err != nil {
			return err
		}
	}
	return nil
}

// methodFor picks a treatment for rcpt. A non-nil error means a lookup failed
// and the recipient fell back to plain.
func (o *Encrypt) methodFor(ctx context.Context, rcpt string) (string, *openpgp.Entity, *x509.Certificate, error) {
	_, domain, _ := strings.Cut(rcpt, "@")
	for _, d := range o.LocalDomains {
		if strings.EqualFold(domain, d) {
			return methodLocal, nil, nil, nil
		}
	}
	var lookupErr error
	for _, p := range o.Prefer {
		switch p {
		case MethodPGP:
			if o.PGP == nil {
				continue
			}
			k, err := o.Keys.PGPKey(ctx, rcpt)
			if err != nil {
				lookupErr = err
			}
			if k != nil && o.acceptable(k.Source) {
				return MethodPGP, k.Entity, nil, nil
			}
		case MethodSMIME:
			if o.SMIME == nil {
				continue
			}
			c, err := o.Keys.SMIMECert(ctx, rcpt)
			if err != nil {
				lookupErr = err
			}
			if c != nil && o.acceptable(c.Source) {
				return MethodSMIME, nil, c.Cert, nil
			}
		}
	}
	if lookupErr != nil {
		o.Log.Warn("encrypt: key lookup failed, treating as no key", "rcpt", rcpt, "err", lookupErr)
	}
	return methodPlain, nil, nil, lookupErr
}

func (o *Encrypt) acceptable(s discover.Source) bool {
	return o.Mode != Strict || slices.Contains(o.StrictSources, s)
}

// advertise adds an Autocrypt header so recipients' clients learn the
// sender's key, unless the client already added one.
func (o *Encrypt) advertise(m *mimeutil.Message, sender string) {
	if !o.AdvertiseAutocrypt || o.PGP == nil || m.Header.Get("Autocrypt") != "" {
		return
	}
	key, ok := o.PGP.AutocryptKey(sender)
	if !ok {
		return
	}
	m.Header.Add("Autocrypt", discover.FormatAutocrypt(sender, o.PreferEncrypt, key))
}

func (o *Encrypt) transform(method string, m *mimeutil.Message, g *group, sender string, alreadySigned bool) ([]byte, error) {
	signer := sender
	if alreadySigned {
		signer = ""
	}
	switch method {
	case methodLocal:
		return m.Bytes(), nil
	case MethodPGP:
		to := g.pgp
		if o.EncryptToSelf {
			if k := o.PGP.LocalKey(sender); k != nil && !slices.Contains(to, k) {
				to = append(slices.Clip(to), k)
			}
		}
		return o.PGP.Encrypt(m, to, signer)
	case MethodSMIME:
		certs := g.certs
		if o.EncryptToSelf {
			if c := o.SMIME.LocalCert(sender); c != nil && !slices.ContainsFunc(certs, c.Equal) {
				certs = append(slices.Clip(certs), c)
			}
		}
		return o.SMIME.Encrypt(m, certs, signer)
	default:
		if signer != "" && o.SMIME != nil && o.SMIME.CanSign(signer) {
			return o.SMIME.Sign(m, signer)
		}
		return m.Bytes(), nil
	}
}

func permanent(format string, args ...any) error {
	return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: fmt.Sprintf(format, args...)}
}
