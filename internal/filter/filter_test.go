package filter

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/brodyhoskins/mailcloak/internal/testkeys"
)

const msg = "From: Alice <alice@corp.example>\n" + // bare LF, as from a pipe
	"To: bob@pgp.example\n" +
	"Subject: hello\n" +
	"\n" +
	"The secret number is 42.\n"

type result struct {
	code           int
	stdout, stderr string
}

// run invokes a filter. Unless args name a -config, a minimal one is used
// that turns network discovery off, so tests never touch the network (and a
// real /etc/mailcloak/mailcloak.yaml never leaks in).
func run(t *testing.T, which string, stdin string, args ...string) result {
	t.Helper()
	if !slices.Contains(args, "-config") {
		args = append([]string{"-config", writeConfig(t, "")}, args...)
	}
	build := map[string]Builder{"encrypt": Encrypt, "decrypt": Decrypt}[which]
	var out, errb bytes.Buffer
	code := Run(which, build, args, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

// writeConfig writes mailcloak.yaml with network discovery disabled plus extra.
func writeConfig(t *testing.T, extra string) string {
	p := filepath.Join(t.TempDir(), "mailcloak.yaml")
	base := "log: none\ndiscovery:\n  wkd: false\n  openpgpkey: false\n  smimea: false\n"
	if err := os.WriteFile(p, []byte(base+extra), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// keys returns a PGP and an S/MIME directory holding private keys for alice
// and bob (PGP) and carol (S/MIME), so one directory serves both directions.
func keys(t *testing.T) (string, string) {
	pgpDir, smimeDir := t.TempDir(), t.TempDir()
	testkeys.PGP(t, pgpDir, "alice@corp.example", true)
	testkeys.PGP(t, pgpDir, "bob@pgp.example", true)
	testkeys.SMIME(t, smimeDir, "alice@corp.example", true)
	testkeys.SMIME(t, smimeDir, "carol@smime.example", true)
	return pgpDir, smimeDir
}

func TestStdinStdoutRoundTrip(t *testing.T) {
	pgpDir, smimeDir := keys(t)

	// Recipients and sender come from the headers when not given.
	enc := run(t, "encrypt", msg, "-pgp", pgpDir, "-smime", smimeDir)
	if enc.code != ExitOK {
		t.Fatalf("encrypt exit %d: %s", enc.code, enc.stderr)
	}
	if !strings.Contains(enc.stdout, "multipart/encrypted") || strings.Contains(enc.stdout, "secret number") {
		t.Fatalf("not PGP encrypted:\n%s", enc.stdout)
	}

	dec := run(t, "decrypt", enc.stdout, "-pgp", pgpDir)
	if dec.code != ExitOK {
		t.Fatalf("decrypt exit %d: %s", dec.code, dec.stderr)
	}
	for _, want := range []string{"Subject: hello", "The secret number is 42.", "X-Mailcloak-Signature: pgp; status=valid"} {
		if !strings.Contains(dec.stdout, want) {
			t.Errorf("decrypted output missing %q:\n%s", want, dec.stdout)
		}
	}
}

func TestDecryptNeedsNoRecipients(t *testing.T) {
	pgpDir, _ := keys(t)
	r := run(t, "decrypt", "Subject: no recipients\n\nhi\n", "-pgp", pgpDir)
	if r.code != ExitOK || !strings.Contains(r.stdout, "hi") {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
}

func TestStdoutRefusesMixedMethods(t *testing.T) {
	pgpDir, smimeDir := keys(t)
	r := run(t, "encrypt", msg, "-pgp", pgpDir, "-smime", smimeDir, "-f", "alice@corp.example", "--", "bob@pgp.example", "carol@smime.example")
	if r.code != ExitUnavailable || r.stdout != "" {
		t.Fatalf("want exit 69 and no output, got %d, %q", r.code, r.stdout)
	}
}

func TestSendmailOutputAndExitCodes(t *testing.T) {
	pgpDir, smimeDir := keys(t)
	dir := t.TempDir()
	argsFile, bodyFile := filepath.Join(dir, "args"), filepath.Join(dir, "body")
	fake := filepath.Join(dir, "sendmail")
	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done >> " + argsFile + "\ncat >> " + bodyFile + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, "sendmail:\n  path: "+fake+"\nencrypt:\n  output: sendmail\n")

	// Mixed recipients are fine with a reinjecting output: one call per group.
	r := run(t, "encrypt", msg, "-config", cfg, "-pgp", pgpDir, "-smime", smimeDir,
		"-f", "", "--", "bob@pgp.example", "carol@smime.example", "dave@plain.example")
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"-G\n-i\n-f\n<>\n--\nbob@pgp.example\n", "--\ncarol@smime.example\n", "--\ndave@plain.example\n"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("sendmail args missing %q:\n%s", want, args)
		}
	}
	body, _ := os.ReadFile(bodyFile)
	for _, want := range []string{"multipart/encrypted", "application/pkcs7-mime", "multipart/signed"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("reinjected mail missing %s", want)
		}
	}

	// A failing sendmail defers (75) rather than bounces.
	os.WriteFile(fake, []byte("#!/bin/sh\necho queue full >&2\nexit 1\n"), 0o755)
	if r := run(t, "encrypt", msg, "-config", cfg, "-pgp", pgpDir); r.code != ExitTempFail {
		t.Fatalf("want 75, got %d: %s", r.code, r.stderr)
	}
}

func TestStrictModeBounces(t *testing.T) {
	pgpDir, _ := keys(t)
	cfg := writeConfig(t, "encrypt:\n  mode: strict\n")
	r := run(t, "encrypt", msg, "-config", cfg, "-pgp", pgpDir, "--", "dave@plain.example")
	if r.code != ExitUnavailable || !strings.HasPrefix(r.stderr, "5.7.1 ") || !strings.Contains(r.stderr, "dave@plain.example") {
		t.Fatalf("want 69 with 5.7.1 reason, got %d: %q", r.code, r.stderr)
	}
}

func TestConfigErrorsDefer(t *testing.T) {
	if r := run(t, "decrypt", msg); r.code != ExitTempFail || !strings.Contains(r.stderr, "no keys configured") {
		t.Fatalf("want 75 for missing keys, got %d: %q", r.code, r.stderr)
	}
	if r := run(t, "decrypt", msg, "-pgp", t.TempDir(), "-listen", "127.0.0.1:0"); r.code != ExitTempFail {
		t.Fatalf("daemon with stdout output must be rejected, got %d", r.code)
	}
}

func TestVersionFlag(t *testing.T) {
	r := run(t, "encrypt", "", "-version")
	if r.code != ExitOK || !strings.HasPrefix(r.stdout, "mailcloak-encrypt ") {
		t.Fatalf("exit %d, %q", r.code, r.stdout)
	}
}
