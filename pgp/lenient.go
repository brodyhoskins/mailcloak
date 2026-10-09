package pgp

import (
	"bytes"
	"errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Packet tags (RFC 9580 section 5).
const (
	tagSecretKey    = 5
	tagPublicKey    = 6
	tagSecretSubkey = 7
	tagPublicSubkey = 14
)

// ParseKeys reads binary or armored keys. go-crypto rejects a whole key if
// any one subkey's binding signature fails to verify; GnuPG instead ignores
// that subkey. To match, if strict parsing fails each subkey is checked on
// its own and only the ones that verify are kept.
func ParseKeys(b []byte) (openpgp.EntityList, error) {
	strict, err := parseStrict(b)
	if err == nil {
		return strict, nil
	}
	lenient, lerr := parseLenient(b)
	if lerr != nil || len(lenient) == 0 {
		return nil, err // report the original problem
	}
	return lenient, nil
}

func parseStrict(b []byte) (openpgp.EntityList, error) {
	if bytes.Contains(b, []byte("-----BEGIN PGP")) {
		return openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	}
	return openpgp.ReadKeyRing(bytes.NewReader(b))
}

type packets []*packet.OpaquePacket

func parseLenient(b []byte) (openpgp.EntityList, error) {
	var r io.Reader = bytes.NewReader(b)
	if bytes.Contains(b, []byte("-----BEGIN PGP")) {
		blk, err := armor.Decode(r)
		if err != nil {
			return nil, err
		}
		r = blk.Body
	}

	// Split the packet stream into one block per primary key.
	var blocks []packets
	or := packet.NewOpaqueReader(r)
	for {
		p, err := or.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if p.Tag == tagPublicKey || p.Tag == tagSecretKey {
			blocks = append(blocks, nil)
		}
		if len(blocks) > 0 {
			blocks[len(blocks)-1] = append(blocks[len(blocks)-1], p)
		}
	}

	var out openpgp.EntityList
	for _, blk := range blocks {
		head, subkeys := splitSubkeys(blk)
		var good []packets
		for _, sk := range subkeys {
			if _, err := readEntity(head, sk); err == nil {
				good = append(good, sk)
			}
		}
		if e, err := readEntity(append([]packets{head}, good...)...); err == nil {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("pgp: no valid keys")
	}
	return out, nil
}

// splitSubkeys separates a key block into the primary key with its user IDs
// and signatures, and one group per subkey (the subkey and its signatures).
func splitSubkeys(blk packets) (head packets, subkeys []packets) {
	for _, p := range blk {
		switch {
		case p.Tag == tagPublicSubkey || p.Tag == tagSecretSubkey:
			subkeys = append(subkeys, packets{p})
		case len(subkeys) > 0:
			subkeys[len(subkeys)-1] = append(subkeys[len(subkeys)-1], p)
		default:
			head = append(head, p)
		}
	}
	return head, subkeys
}

func readEntity(groups ...packets) (*openpgp.Entity, error) {
	var buf bytes.Buffer
	for _, g := range groups {
		for _, p := range g {
			if err := p.Serialize(&buf); err != nil {
				return nil, err
			}
		}
	}
	return openpgp.ReadEntity(packet.NewReader(&buf))
}
