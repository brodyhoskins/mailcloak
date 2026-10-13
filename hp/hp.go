// Package hp implements Header Protection for encrypted mail (RFC 9788).
//
// The sender copies the header fields into the encrypted part, marks it with
// hp="cipher", and replaces the Subject outside with "[...]" (the baseline
// policy, hcp_baseline). The recipient takes the header fields from inside
// again. Servers on the way, which can add tags such as "***UNCHECKED***" to
// the outer Subject, never see the real one.
package hp

import (
	"bytes"
	"encoding/base64"
	"html"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/brodyhoskins/mailcloak/mimeutil"
)

// Obscured is the Subject outside an encrypted message.
const Obscured = "[...]"

// structural reports whether a header field describes the MIME structure
// rather than the message (RFC 9787 section 1.1.1).
func structural(name string) bool {
	return mimeutil.IsContentField(name) || strings.EqualFold(name, "MIME-Version")
}

// baseline is hcp_baseline (RFC 9788 section 3.2.1): the value a field gets
// outside, and false when it is removed.
func baseline(name, value string) (string, bool) {
	switch strings.ToLower(name) {
	case "subject":
		return Obscured, true
	case "comments", "keywords":
		return "", false
	}
	return value, true
}

// Protect splits m for encryption with Header Protection (RFC 9788 section
// 5.2). outer is the header that goes outside the encryption. entity is the
// Cryptographic Payload, the part to sign and encrypt: it holds every
// header field of m, an HP-Outer field for each field in outer, and a
// Legacy Display Element in the main body parts, so that a client without
// Header Protection that can decrypt still shows the Subject. m is not
// changed.
func Protect(m *mimeutil.Message) (outer mimeutil.Header, entity []byte) {
	var fields, content, legacy mimeutil.Header
	for _, f := range m.Header {
		if structural(f.Name) {
			if !strings.EqualFold(f.Name, "MIME-Version") {
				content = append(content, f)
			}
			continue
		}
		fields = append(fields, f)
		v, keep := baseline(f.Name, f.Value())
		switch {
		case !keep:
		case v == f.Value():
			outer = append(outer, f)
		default:
			outer.Add(f.Name, v)
		}
		if !keep || v != f.Value() {
			legacy.Add(f.Name, decodeWords(f.Value()))
		}
	}

	part := &mimeutil.Message{Header: content, Body: m.Body}
	if len(legacy) > 0 {
		part = addLegacyDisplay(part, legacy)
	}
	mt, params := part.Header.MediaType()
	params["hp"] = "cipher"
	h := append(mimeutil.Header{}, fields...)
	h = append(h, part.Header.Without(func(n string) bool { return strings.EqualFold(n, "Content-Type") })...)
	h.Add("Content-Type", mime.FormatMediaType(mt, params))
	for _, f := range outer {
		h.Add("HP-Outer", f.Name+": "+f.Value())
	}
	return outer, (&mimeutil.Message{Header: h, Body: part.Body}).Bytes()
}

// Unprotect builds the message to show from the header outside the
// encryption and the decrypted (and unsigned) entity, as
// mimeutil.JoinEntity does. If the entity has Header Protection (hp="clear"
// or "cipher", or protected-headers="v1" of the older drafts), its header
// fields replace those of the same name outside (RFC 9788 section 4.5),
// HP-Outer fields are dropped, and so are Legacy Display Elements (section
// 4.5.3). The outer From stays when the inner From has another address,
// since the provider vouched for the outer one (section 4.4.3).
func Unprotect(outer mimeutil.Header, entity []byte) ([]byte, error) {
	e, err := mimeutil.Parse(entity)
	if err != nil {
		return nil, err
	}
	mt, params := e.Header.MediaType()
	if !protected(params) {
		return mimeutil.JoinEntity(outer, entity)
	}

	var inner mimeutil.Header
	names := map[string]bool{}
	for _, f := range e.Header {
		if structural(f.Name) || strings.EqualFold(f.Name, "HP-Outer") {
			continue
		}
		if strings.EqualFold(f.Name, "From") && !sameAddress(f.Value(), outer.Get("From")) {
			continue
		}
		inner = append(inner, f)
		names[strings.ToLower(f.Name)] = true
	}
	h := outer.Without(func(n string) bool { return names[strings.ToLower(n)] })
	h = append(h, inner...)

	delete(params, "hp")
	delete(params, "protected-headers")
	part := &mimeutil.Message{Header: e.Header.Without(func(n string) bool { return !mimeutil.IsContentField(n) }), Body: e.Body}
	part.Header.Set("Content-Type", mime.FormatMediaType(mt, params))
	part = dropLegacyDisplay(part)
	var b bytes.Buffer
	b.Write(part.Header.Bytes())
	b.WriteString("\r\n")
	b.Write(part.Body)
	return mimeutil.JoinEntity(h, b.Bytes())
}

func protected(params map[string]string) bool {
	switch strings.ToLower(params["hp"]) {
	case "clear", "cipher":
		return true
	}
	return params["protected-headers"] == "v1"
}

func sameAddress(a, b string) bool {
	x, err1 := mail.ParseAddress(a)
	y, err2 := mail.ParseAddress(b)
	return err1 == nil && err2 == nil && strings.EqualFold(x.Address, y.Address)
}

// decodeWords decodes RFC 2047 encoded words for the Legacy Display
// Element, which is body text.
func decodeWords(v string) string {
	if d, err := new(mime.WordDecoder).DecodeHeader(v); err == nil {
		return d
	}
	return v
}

// mainBodyParts calls fn on each main body part of m (RFC 9787 section
// 7.1): the first child of multipart/mixed and multipart/related, every
// child of multipart/alternative, down to text/plain or text/html parts that
// are not attachments. fn returns the new part. It returns m itself if
// nothing changed.
func mainBodyParts(m *mimeutil.Message, fn func(*mimeutil.Message) *mimeutil.Message) *mimeutil.Message {
	mt, params := m.Header.MediaType()
	switch mt {
	case "text/plain", "text/html":
		if d, _, _ := mime.ParseMediaType(m.Header.Get("Content-Disposition")); d == "attachment" {
			return m
		}
		return fn(m)
	case "multipart/mixed", "multipart/related", "multipart/alternative":
	default:
		return m
	}
	pre, parts, post, ok := mimeutil.Parts(m.Body, params["boundary"])
	if !ok || len(parts) == 0 {
		return m
	}
	changed := false
	for i, p := range parts {
		if i > 0 && mt != "multipart/alternative" {
			break
		}
		pm, err := mimeutil.Parse(p)
		if err != nil {
			continue
		}
		if np := mainBodyParts(pm, fn); np != pm {
			parts[i], changed = np.Bytes(), true
		}
	}
	if !changed {
		return m
	}
	return &mimeutil.Message{Header: m.Header, Body: mimeutil.JoinParts(pre, parts, post, params["boundary"])}
}

// addLegacyDisplay puts the fields in legacy at the top of each main body
// part (RFC 9788 sections 5.2.2 and 5.2.3).
func addLegacyDisplay(m *mimeutil.Message, legacy mimeutil.Header) *mimeutil.Message {
	var text strings.Builder
	for _, f := range legacy {
		text.WriteString(f.Name + ": " + f.Value() + "\r\n")
	}
	return mainBodyParts(m, func(p *mimeutil.Message) *mimeutil.Message {
		mt, params := p.Header.MediaType()
		ascii := isASCII(text.String())
		switch cs := strings.ToLower(params["charset"]); {
		case ascii, cs == "utf-8", cs == "utf8":
		case cs == "" || cs == "us-ascii":
			params["charset"] = "utf-8"
		default:
			return p // the fields cannot be written in this charset
		}
		content, ok := decodeBody(p)
		if !ok {
			return p
		}
		if mt == "text/html" {
			div := []byte("<div class=\"header-protection-legacy-display\"><pre>" + html.EscapeString(strings.TrimSuffix(text.String(), "\r\n")) + "</pre></div>\r\n")
			at := 0
			if loc := bodyTag.FindIndex(content); loc != nil {
				at = loc[1]
				div = append([]byte("\r\n"), div...)
			}
			content = append(append(append([]byte{}, content[:at]...), div...), content[at:]...)
		} else {
			content = append([]byte(text.String()+"\r\n"), content...)
		}
		params["hp-legacy-display"] = "1"
		p.Header.Set("Content-Type", mime.FormatMediaType(mt, params))
		return encodeBody(p, content)
	})
}

// dropLegacyDisplay removes the Legacy Display Elements from parts marked
// hp-legacy-display="1" (RFC 9788 section 4.5.3), and the text/rfc822-headers
// parts with protected-headers="v1" that the older drafts used instead.
func dropLegacyDisplay(m *mimeutil.Message) *mimeutil.Message {
	if mt, params := m.Header.MediaType(); mt == "multipart/mixed" {
		if pre, parts, post, ok := mimeutil.Parts(m.Body, params["boundary"]); ok && len(parts) > 1 {
			if pm, err := mimeutil.Parse(parts[0]); err == nil {
				if pt, pp := pm.Header.MediaType(); pt == "text/rfc822-headers" && pp["protected-headers"] == "v1" {
					m = &mimeutil.Message{Header: m.Header, Body: mimeutil.JoinParts(pre, parts[1:], post, params["boundary"])}
				}
			}
		}
	}
	return mainBodyParts(m, func(p *mimeutil.Message) *mimeutil.Message {
		mt, params := p.Header.MediaType()
		if params["hp-legacy-display"] != "1" {
			return p
		}
		content, ok := decodeBody(p)
		if !ok {
			return p
		}
		if mt == "text/html" {
			loc := legacyDiv.FindIndex(content)
			if loc == nil {
				return p
			}
			content = append(append([]byte{}, content[:loc[0]]...), content[loc[1]:]...)
		} else {
			// Up to and including the first blank line.
			i := bytes.Index(content, []byte("\r\n\r\n"))
			if i < 0 {
				return p
			}
			content = content[i+4:]
		}
		delete(params, "hp-legacy-display")
		p.Header.Set("Content-Type", mime.FormatMediaType(mt, params))
		return encodeBody(p, content)
	})
}

var (
	bodyTag   = regexp.MustCompile(`(?i)<body\b[^>]*>`)
	legacyDiv = regexp.MustCompile(`(?is)\s*<div\b[^>]*\bclass\s*=\s*["']?header-protection-legacy-display\b[^>]*>.*?</div>[ \t]*(\r\n)?`)
)

// decodeBody undoes the part's Content-Transfer-Encoding.
func decodeBody(p *mimeutil.Message) ([]byte, bool) {
	switch strings.ToLower(p.Header.Get("Content-Transfer-Encoding")) {
	case "", "7bit", "8bit", "binary":
		return p.Body, true
	case "base64":
		b, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(p.Body), nil)))
		return mimeutil.CRLF(b), err == nil
	case "quoted-printable":
		b, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(p.Body)))
		return mimeutil.CRLF(b), err == nil
	}
	return nil, false
}

// encodeBody sets the part's body to content in its transfer encoding.
// Non-ASCII text in a 7bit part makes it quoted-printable.
func encodeBody(p *mimeutil.Message, content []byte) *mimeutil.Message {
	q := &mimeutil.Message{Header: append(mimeutil.Header{}, p.Header...)}
	cte := strings.ToLower(q.Header.Get("Content-Transfer-Encoding"))
	if (cte == "" || cte == "7bit") && !isASCII(string(content)) {
		cte = "quoted-printable"
		q.Header.Set("Content-Transfer-Encoding", cte)
	}
	switch cte {
	case "base64":
		q.Body = mimeutil.Base64Lines(content)
	case "quoted-printable":
		var b bytes.Buffer
		w := quotedprintable.NewWriter(&b)
		w.Write(content)
		w.Close()
		q.Body = mimeutil.CRLF(b.Bytes())
	default:
		q.Body = content
	}
	// A part in a multipart body ends where the CRLF of the next delimiter
	// starts.
	if !bytes.HasSuffix(p.Body, []byte("\r\n")) {
		q.Body = bytes.TrimSuffix(q.Body, []byte("\r\n"))
	}
	return q
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
