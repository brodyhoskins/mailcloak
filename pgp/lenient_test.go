package pgp

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/brodyhoskins/mailcloak/internal/testkeys"
)

func TestParseKeysDropsBadSubkey(t *testing.T) {
	ent := testkeys.NewPGP(t, "werner@example.org")
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519}
	if err := ent.AddEncryptionSubkey(cfg); err != nil {
		t.Fatal(err)
	}
	good := ent.Subkeys[0].PublicKey.KeyId

	// Corrupt the binding signature of the second subkey: flip a byte near
	// the end of the last packet (inside the signature value).
	raw := testkeys.PublicBytes(t, ent)
	var pkts packets
	or := packet.NewOpaqueReader(bytes.NewReader(raw))
	for {
		p, err := or.Next()
		if err != nil {
			break
		}
		pkts = append(pkts, p)
	}
	last := pkts[len(pkts)-1]
	last.Contents[len(last.Contents)-3] ^= 0xff
	var buf bytes.Buffer
	for _, p := range pkts {
		p.Serialize(&buf)
	}

	if _, err := parseStrict(buf.Bytes()); err == nil {
		t.Fatal("test setup: strict parsing should reject the corrupted key")
	}
	list, err := ParseKeys(buf.Bytes())
	if err != nil || len(list) != 1 {
		t.Fatalf("lenient parse: %v (%d entities)", err, len(list))
	}
	e := list[0]
	if len(e.Subkeys) != 1 || e.Subkeys[0].PublicKey.KeyId != good {
		t.Fatalf("want only the valid subkey, got %d subkeys", len(e.Subkeys))
	}
	if k, ok := e.EncryptionKey(time.Now()); !ok || k.PublicKey.KeyId != good {
		t.Fatal("valid subkey not usable for encryption")
	}
}
