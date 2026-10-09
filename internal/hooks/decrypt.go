package hooks

import (
	"context"
	"log/slog"
	"strings"

	"github.com/brodyhoskins/mailcloak/discover"
	"github.com/brodyhoskins/mailcloak/internal/pipeline"
	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/pgp"
	"github.com/brodyhoskins/mailcloak/smime"
)

// Header fields Decrypt adds. Any copies arriving from outside are stripped so
// they can't be spoofed.
const (
	HeaderDecrypted = "X-Mailcloak-Decrypted"
	HeaderSignature = "X-Mailcloak-Signature"
)

// Decrypt decrypts mail arriving for the organisation. Messages it can't
// decrypt (no matching key, unsupported format) are delivered unchanged so the
// recipient can still try to decrypt them client-side.
type Decrypt struct {
	PGP     *pgp.Engine
	SMIME   *smime.Engine
	Harvest *discover.Harvester // nil disables learning senders' keys
	Log     *slog.Logger
}

func (in *Decrypt) Middleware(next pipeline.Handler) pipeline.Handler {
	return pipeline.HandlerFunc(func(ctx context.Context, env *pipeline.Envelope) error {
		m, err := mimeutil.Parse(env.Data)
		if err != nil {
			in.Log.Warn("decrypt: unparseable message, passing through", "err", err)
			return next.Handle(ctx, env)
		}
		m.Header = m.Header.Without(func(n string) bool { return strings.HasPrefix(strings.ToLower(n), "x-mailcloak-") })

		out := in.decrypt(m)
		if in.Harvest != nil {
			if final, err := mimeutil.Parse(out); err == nil {
				in.Harvest.Harvest(m, final)
			}
		}
		return next.Handle(ctx, &pipeline.Envelope{From: env.From, To: env.To, Data: out})
	})
}

func (in *Decrypt) decrypt(m *mimeutil.Message) []byte {
	switch {
	case in.PGP != nil && pgp.IsEncrypted(m):
		res, err := in.PGP.Decrypt(m)
		if err != nil {
			in.Log.Warn("decrypt: pgp decrypt failed, passing through", "err", err)
			break
		}
		dm, err := mimeutil.Parse(res.Message)
		if err != nil {
			break
		}
		// Decryption strips the PGP signature along with the envelope, so
		// record the verification result for the client.
		dm.Header = prepend(dm.Header, HeaderDecrypted, "pgp")
		sig := "pgp; status=" + string(res.Signature)
		if res.Signer != "" {
			sig += "; signer=" + res.Signer
		}
		dm.Header = prepend(dm.Header, HeaderSignature, sig)
		in.Log.Info("decrypt: decrypted", "method", "pgp", "signature", res.Signature)
		return dm.Bytes()

	case in.SMIME != nil && smime.IsEncrypted(m):
		plain, err := in.SMIME.Decrypt(m)
		if err != nil {
			in.Log.Warn("decrypt: smime decrypt failed, passing through", "err", err)
			break
		}
		dm, err := mimeutil.Parse(plain)
		if err != nil {
			break
		}
		// Any inner S/MIME signature is left intact for the client to verify.
		dm.Header = prepend(dm.Header, HeaderDecrypted, "smime")
		in.Log.Info("decrypt: decrypted", "method", "smime")
		return dm.Bytes()
	}
	return m.Bytes()
}

func prepend(h mimeutil.Header, name, value string) mimeutil.Header {
	var f mimeutil.Header
	f.Add(name, value)
	return append(f, h...)
}
