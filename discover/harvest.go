package discover

import (
	"bytes"
	"crypto/x509"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/brodyhoskins/mailcloak/mimeutil"
	"github.com/brodyhoskins/mailcloak/smime"
)

// autocryptPeer is the Autocrypt Level 1 peer state for one address.
type autocryptPeer struct {
	Addr          string    `json:"addr"`
	LastSeen      time.Time `json:"last_seen"`
	Timestamp     time.Time `json:"autocrypt_timestamp"`
	Key           []byte    `json:"key"`
	PreferEncrypt string    `json:"prefer_encrypt"`
}

// harvestedCert is a certificate collected from a signed incoming message.
type harvestedCert struct {
	Addr string    `json:"addr"`
	Seen time.Time `json:"seen"`
	Cert []byte    `json:"cert"` // DER
}

// Harvester learns senders' keys from incoming mail.
type Harvester struct {
	Store      *Store
	Autocrypt  bool
	SMIME      bool
	SMIMERoots *x509.CertPool // harvested certificates must chain to these
	Log        *slog.Logger
	Now        func() time.Time
}

func (h *Harvester) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Harvest inspects a message. original is the message as received (where
// Autocrypt headers are); final is after decryption (where an S/MIME
// signature may be).
func (h *Harvester) Harvest(original, final *mimeutil.Message) {
	from := singleFrom(original.Header)
	if from == "" {
		return
	}
	if h.Autocrypt {
		if err := h.autocrypt(original, from); err != nil {
			h.Log.Warn("harvest: autocrypt update failed", "from", from, "err", err)
		}
	}
	if h.SMIME {
		h.smime(final, from)
	}
}

// autocrypt applies the Autocrypt Level 1 "update peer state" rules.
func (h *Harvester) autocrypt(m *mimeutil.Message, from string) error {
	if mt, _ := m.Header.MediaType(); mt == "multipart/report" {
		return nil // bounces and receipts are not from the peer's client
	}
	var valid []*Autocrypt
	for _, f := range m.Header {
		if f.Name != "Autocrypt" {
			continue
		}
		a, err := ParseAutocrypt(f.Value())
		if err != nil || a.Addr != from || selectKey(a.KeyData, from) == nil {
			continue
		}
		valid = append(valid, a)
	}
	var hdr *Autocrypt
	if len(valid) == 1 { // more than one valid header: use none
		hdr = valid[0]
	}

	date := h.now()
	if d, err := mail.ParseDate(m.Header.Get("Date")); err == nil && d.Before(date) {
		date = d
	}

	var p autocryptPeer
	return h.Store.Update(kindAutocrypt, from, &p, func(exists bool) bool {
		if !exists && hdr == nil {
			return false // don't track every sender, only Autocrypt users
		}
		p.Addr = from
		changed := false
		if date.After(p.LastSeen) {
			p.LastSeen, changed = date, true
		}
		if hdr != nil && date.After(p.Timestamp) {
			p.Timestamp, p.Key, p.PreferEncrypt = date, hdr.KeyData, hdr.PreferEncrypt
			h.Log.Info("harvest: autocrypt key", "addr", from, "prefer_encrypt", hdr.PreferEncrypt)
			changed = true
		}
		return changed
	})
}

func (h *Harvester) smime(m *mimeutil.Message, from string) {
	cert, _, err := smime.VerifySigned(m, h.SMIMERoots)
	if err != nil {
		return // unsigned, or a signature we won't trust
	}
	match := false
	for _, a := range smime.Addresses(cert) {
		match = match || a == from
	}
	if !match || !smime.Usable(cert) {
		return
	}
	var rec harvestedCert
	err = h.Store.Update(kindSMIME, from, &rec, func(exists bool) bool {
		if exists && bytes.Equal(rec.Cert, cert.Raw) {
			return false
		}
		if exists {
			// Keep the newer of two valid certificates.
			if old, err := x509.ParseCertificate(rec.Cert); err == nil && smime.Usable(old) && old.NotBefore.After(cert.NotBefore) {
				return false
			}
		}
		rec = harvestedCert{Addr: from, Seen: h.now(), Cert: cert.Raw}
		h.Log.Info("harvest: smime certificate", "addr", from, "serial", cert.SerialNumber.String())
		return true
	})
	if err != nil {
		h.Log.Warn("harvest: smime store failed", "from", from, "err", err)
	}
}

func singleFrom(h mimeutil.Header) string {
	list, err := mail.ParseAddressList(h.Get("From"))
	if err != nil || len(list) != 1 {
		return ""
	}
	return strings.ToLower(list[0].Address)
}
