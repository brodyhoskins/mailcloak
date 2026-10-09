// Package pipeline defines the message envelope that flows through a core and
// the middleware contract that crypto hooks implement.
package pipeline

import "context"

// Envelope is a single SMTP transaction: the reverse path, the forward paths
// and the raw RFC 5322 message.
type Envelope struct {
	From string
	To   []string
	Data []byte
}

// Clone returns a copy of the envelope that shares nothing with the original.
func (e *Envelope) Clone() *Envelope {
	return &Envelope{
		From: e.From,
		To:   append([]string(nil), e.To...),
		Data: append([]byte(nil), e.Data...),
	}
}

// Handler processes an envelope. The terminal handler of a core is the
// forwarder that relays the message to the next hop.
type Handler interface {
	Handle(ctx context.Context, env *Envelope) error
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, env *Envelope) error

func (f HandlerFunc) Handle(ctx context.Context, env *Envelope) error { return f(ctx, env) }

// Middleware wraps a Handler. A middleware may rewrite the envelope, call next
// zero or more times (e.g. once per recipient group), or reject the message.
type Middleware func(next Handler) Handler

// Chain wraps h with mw so that mw[0] is the outermost middleware.
func Chain(h Handler, mw ...Middleware) Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
