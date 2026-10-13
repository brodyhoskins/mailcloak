package hp

import (
	"strings"
	"testing"

	"github.com/brodyhoskins/mailcloak/mimeutil"
)

const msg = "From: Alice <alice@corp.example>\r\n" +
	"To: bob@pgp.example\r\n" +
	"Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\n" +
	"Keywords: secret\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/alternative; boundary=\"b\"\r\n" +
	"\r\n" +
	"--b\r\n" +
	"Content-Type: text/plain; charset=us-ascii\r\n" +
	"\r\n" +
	"Hello.\r\n" +
	"--b\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"PGh0bWw+PGJvZHkgc3R5bGU9IngiPjxwPkhlbGxvLjwvcD48L2JvZHk+PC9odG1sPg==\r\n" +
	"--b--\r\n"

func TestProtect(t *testing.T) {
	m, err := mimeutil.Parse([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	outer, entity := Protect(m)
	if got := outer.Get("Subject"); got != Obscured {
		t.Errorf("outer Subject = %q", got)
	}
	if outer.Get("Keywords") != "" || outer.Get("From") != "Alice <alice@corp.example>" {
		t.Errorf("outer header:\n%s", outer.Bytes())
	}
	e, err := mimeutil.Parse(entity)
	if err != nil {
		t.Fatal(err)
	}
	if _, p := e.Header.MediaType(); p["hp"] != "cipher" {
		t.Errorf("payload Content-Type = %q", e.Header.Get("Content-Type"))
	}
	for _, want := range []string{
		"Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\n",
		"Keywords: secret\r\n",
		"HP-Outer: Subject: [...]\r\n",
		"HP-Outer: From: Alice <alice@corp.example>\r\n",
		"hp-legacy-display=1",
		"Content-Transfer-Encoding: quoted-printable",
		"Subject: Gr=C3=BC=C3=9Fe\r\nKeywords: secret\r\n\r\nHello.",
	} {
		if !strings.Contains(string(entity), want) {
			t.Errorf("payload lacks %q:\n%s", want, entity)
		}
	}
	if strings.Contains(string(entity), "HP-Outer: Keywords") {
		t.Error("a removed field has an HP-Outer copy")
	}

	// The recipient gets the message back, apart from Content-Type
	// parameter formatting.
	out, err := Unprotect(append(outer, mimeutil.Field{Name: "Received", Raw: "Received: from mx\r\n"}), entity)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mimeutil.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if s := got.Header.Get("Subject"); s != "=?utf-8?q?Gr=C3=BC=C3=9Fe?=" {
		t.Errorf("Subject = %q", s)
	}
	for _, name := range []string{"Subject", "From", "To", "Keywords", "Received"} {
		if n := count(got.Header, name); n != 1 {
			t.Errorf("%d %s fields:\n%s", n, name, got.Header.Bytes())
		}
	}
	for _, bad := range []string{"HP-Outer", "hp=", "hp-legacy-display", "Subject: Gr=C3", "header-protection-legacy-display"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("result has %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(string(out), "\r\n\r\nHello.\r\n--b") {
		t.Errorf("text part not restored:\n%s", out)
	}
	html, _ := decodeBody(mustPart(t, got, 1))
	if string(html) != `<html><body style="x"><p>Hello.</p></body></html>` {
		t.Errorf("html part = %q", html)
	}
}

func TestUnprotectKeepsOuterFrom(t *testing.T) {
	var outer mimeutil.Header
	outer.Add("From", "Mallory <mallory@evil.example>")
	outer.Add("Subject", "***UNCHECKED*** [...]")
	entity := "From: Boss <boss@corp.example>\r\nSubject: Wire the money\r\nContent-Type: text/plain; hp=\"cipher\"\r\n\r\nNow.\r\n"
	out, err := Unprotect(outer, []byte(entity))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := mimeutil.Parse(out)
	if f := m.Header.Get("From"); f != "Mallory <mallory@evil.example>" || count(m.Header, "From") != 1 {
		t.Errorf("From = %q:\n%s", f, out)
	}
	if s := m.Header.Get("Subject"); s != "Wire the money" {
		t.Errorf("Subject = %q", s)
	}
}

func TestUnprotectWithoutHeaderProtection(t *testing.T) {
	var outer mimeutil.Header
	outer.Add("Subject", "***UNCHECKED*** Hi")
	out, err := Unprotect(outer, []byte("Content-Type: text/plain\r\n\r\nHi.\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "Subject: ***UNCHECKED*** Hi\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nHi.\r\n"; string(out) != want {
		t.Errorf("got\n%s", out)
	}
}

func TestUnprotectDraftLegacyPart(t *testing.T) {
	var outer mimeutil.Header
	outer.Add("Subject", "...")
	entity := "Subject: Real\r\nContent-Type: multipart/mixed; boundary=\"x\"; protected-headers=\"v1\"\r\n\r\n" +
		"--x\r\nContent-Type: text/rfc822-headers; protected-headers=\"v1\"\r\nContent-Disposition: inline\r\n\r\nSubject: Real\r\n" +
		"--x\r\nContent-Type: text/plain\r\n\r\nBody.\r\n--x--\r\n"
	out, err := Unprotect(outer, []byte(entity))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "rfc822-headers") || !strings.Contains(string(out), "Subject: Real\r\n") || strings.Contains(string(out), "Subject: ...") {
		t.Errorf("got\n%s", out)
	}
}

func TestParts(t *testing.T) {
	body := "pre\r\n--b\r\nA\r\n--b \r\n\r\nB\r\n\r\n--b--\r\nepi\r\n"
	pre, parts, post, ok := mimeutil.Parts([]byte(body), "b")
	if !ok || string(pre) != "pre" || len(parts) != 2 || string(parts[0]) != "A" || string(parts[1]) != "\r\nB\r\n" || string(post) != "epi\r\n" {
		t.Fatalf("Parts = %q %q %q %v", pre, parts, post, ok)
	}
	if got := mimeutil.JoinParts(pre, parts, post, "b"); string(got) != strings.Replace(body, "--b \r\n", "--b\r\n", 1) {
		t.Errorf("JoinParts = %q", got)
	}
}

func count(h mimeutil.Header, name string) int {
	n := 0
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			n++
		}
	}
	return n
}

func mustPart(t *testing.T, m *mimeutil.Message, i int) *mimeutil.Message {
	t.Helper()
	_, params := m.Header.MediaType()
	_, parts, _, ok := mimeutil.Parts(m.Body, params["boundary"])
	if !ok || len(parts) <= i {
		t.Fatalf("no part %d", i)
	}
	p, err := mimeutil.Parse(parts[i])
	if err != nil {
		t.Fatal(err)
	}
	return p
}
