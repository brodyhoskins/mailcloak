package version

import (
	"strings"
	"testing"
)

func TestToken(t *testing.T) {
	if !strings.HasPrefix(Token(), "mailcloak/") || String() == "" {
		t.Fatalf("Token = %q", Token())
	}
	// Product tokens can't contain spaces or separators like "/" or "(".
	if strings.ContainsAny(String(), " /()<>@,;:\\\"[]?={}") {
		t.Fatalf("version %q is not a valid token", String())
	}
}
