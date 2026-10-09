package discover

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Autocrypt is a parsed Autocrypt Level 1 header.
type Autocrypt struct {
	Addr          string
	PreferEncrypt string // "mutual" or "nopreference"
	KeyData       []byte // binary OpenPGP public key
}

// ParseAutocrypt parses an unfolded Autocrypt header value. Per the spec,
// unknown attributes are an error unless they start with "_".
func ParseAutocrypt(v string) (*Autocrypt, error) {
	a := &Autocrypt{PreferEncrypt: "nopreference"}
	for _, attr := range strings.Split(v, ";") {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		k, val, ok := strings.Cut(attr, "=")
		if !ok {
			return nil, fmt.Errorf("autocrypt: malformed attribute %q", attr)
		}
		switch k = strings.TrimSpace(k); {
		case k == "addr":
			a.Addr = strings.ToLower(strings.TrimSpace(val))
		case k == "prefer-encrypt":
			if strings.TrimSpace(val) == "mutual" {
				a.PreferEncrypt = "mutual"
			}
		case k == "keydata":
			b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(val), ""))
			if err != nil {
				return nil, fmt.Errorf("autocrypt: keydata: %w", err)
			}
			a.KeyData = b
		case strings.HasPrefix(k, "_"):
		default:
			return nil, fmt.Errorf("autocrypt: unknown critical attribute %q", k)
		}
	}
	if a.Addr == "" || len(a.KeyData) == 0 {
		return nil, errors.New("autocrypt: addr and keydata are required")
	}
	return a, nil
}

// FormatAutocrypt renders a folded header value (without the field name).
func FormatAutocrypt(addr, preferEncrypt string, key []byte) string {
	var b strings.Builder
	b.WriteString("addr=" + addr + ";")
	if preferEncrypt == "mutual" {
		b.WriteString(" prefer-encrypt=mutual;")
	}
	b.WriteString(" keydata=")
	enc := base64.StdEncoding.EncodeToString(key)
	for len(enc) > 0 {
		n := min(len(enc), 76)
		b.WriteString("\r\n " + enc[:n])
		enc = enc[n:]
	}
	return b.String()
}
