// Package mimeutil contains the small amount of byte-exact MIME handling that
// signing and encryption need: splitting a message into its transport headers
// and its body entity, and re-assembling it afterwards.
package mimeutil

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"mime"
	"net/mail"
	"strings"
)

// Field is a single header field with its original (possibly folded) bytes.
type Field struct {
	Name string // canonical-case name, e.g. "Content-Type"
	Raw  string // full field including name and trailing CRLF
}

// Value returns the unfolded field value.
func (f Field) Value() string {
	_, v, _ := strings.Cut(f.Raw, ":")
	v = strings.ReplaceAll(v, "\r\n", "")
	v = strings.ReplaceAll(v, "\n", "")
	return strings.TrimSpace(v)
}

// Header is an ordered list of header fields.
type Header []Field

// Get returns the unfolded value of the first field named name.
func (h Header) Get(name string) string {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return f.Value()
		}
	}
	return ""
}

// Without returns a copy of h with every field for which drop returns true removed.
func (h Header) Without(drop func(name string) bool) Header {
	out := make(Header, 0, len(h))
	for _, f := range h {
		if !drop(f.Name) {
			out = append(out, f)
		}
	}
	return out
}

// Add appends a field. value must already be suitably encoded.
func (h *Header) Add(name, value string) {
	*h = append(*h, Field{Name: name, Raw: name + ": " + value + "\r\n"})
}

// Bytes serialises the header without the terminating blank line.
func (h Header) Bytes() []byte {
	var b bytes.Buffer
	for _, f := range h {
		b.WriteString(f.Raw)
	}
	return b.Bytes()
}

// Message is a parsed RFC 5322 message.
type Message struct {
	Header Header
	Body   []byte
}

// Parse splits raw into header fields and body. Line endings are normalised to
// CRLF first so that output is canonical for signing.
func Parse(raw []byte) (*Message, error) {
	raw = CRLF(raw)
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	var head, body []byte
	switch {
	case bytes.HasPrefix(raw, []byte("\r\n")):
		body = raw[2:]
	case end < 0:
		head = raw
	default:
		head, body = raw[:end+2], raw[end+4:]
	}

	var h Header
	for len(head) > 0 {
		i := bytes.Index(head, []byte("\r\n"))
		var line []byte
		if i < 0 {
			line, head = append(head, '\r', '\n'), nil
		} else {
			line, head = head[:i+2], head[i+2:]
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(h) == 0 {
				return nil, errors.New("mimeutil: continuation line before first header")
			}
			h[len(h)-1].Raw += string(line)
			continue
		}
		name, _, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return nil, errors.New("mimeutil: malformed header line")
		}
		h = append(h, Field{Name: canonical(string(bytes.TrimSpace(name))), Raw: string(line)})
	}
	return &Message{Header: h, Body: body}, nil
}

// Bytes serialises the message.
func (m *Message) Bytes() []byte {
	var b bytes.Buffer
	b.Write(m.Header.Bytes())
	b.WriteString("\r\n")
	b.Write(m.Body)
	return b.Bytes()
}

// IsContentField reports whether a header field describes the body entity
// rather than the transport envelope (RFC 2045 section 9).
func IsContentField(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "content-")
}

// SplitEntity separates m into its transport headers (From, To, Subject, ...)
// and the body MIME entity (Content-* headers plus body). The entity is what
// gets signed or encrypted.
func (m *Message) SplitEntity() (outer Header, entity []byte) {
	outer = m.Header.Without(IsContentField)
	inner := m.Header.Without(func(n string) bool { return !IsContentField(n) })
	var b bytes.Buffer
	b.Write(inner.Bytes())
	b.WriteString("\r\n")
	b.Write(m.Body)
	return outer, b.Bytes()
}

// JoinEntity builds a message from transport headers and a MIME entity, which
// must start with its own header block.
func JoinEntity(outer Header, entity []byte) ([]byte, error) {
	e, err := Parse(entity)
	if err != nil {
		return nil, err
	}
	h := outer.Without(func(n string) bool { return IsContentField(n) || strings.EqualFold(n, "MIME-Version") })
	h.Add("MIME-Version", "1.0")
	h = append(h, e.Header...)
	return (&Message{Header: h, Body: e.Body}).Bytes(), nil
}

// MediaType parses the Content-Type of h, defaulting to text/plain.
func (h Header) MediaType() (string, map[string]string) {
	ct := h.Get("Content-Type")
	if ct == "" {
		return "text/plain", map[string]string{}
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return "application/octet-stream", map[string]string{}
	}
	return mt, params
}

// FromAddress returns the bare address of the From header, or "".
func (h Header) FromAddress() string {
	a, err := mail.ParseAddress(h.Get("From"))
	if err != nil {
		return ""
	}
	return strings.ToLower(a.Address)
}

// Boundary returns a fresh random multipart boundary.
func Boundary() string {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "mailcloak-" + hex.EncodeToString(b[:])
}

// Base64Lines encodes data as base64 wrapped at 76 columns with CRLF.
func Base64Lines(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var b bytes.Buffer
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
	return b.Bytes()
}

// CRLF converts bare LF line endings to CRLF.
func CRLF(b []byte) []byte {
	if !bytes.Contains(b, []byte("\n")) {
		return b
	}
	out := make([]byte, 0, len(b)+len(b)/40)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

func canonical(name string) string {
	parts := strings.Split(strings.ToLower(name), "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}
