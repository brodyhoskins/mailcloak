// Package discover finds recipients' keys beyond the local key directories:
// Web Key Directory, a keyserver, and keys harvested from incoming mail
// (Autocrypt headers and S/MIME signatures).
package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Store is a directory of small JSON records, one per (kind, address). Writes
// are atomic (temp file + rename), so concurrent filter processes never see a
// partial record; Update serialises read-modify-write with flock.
//
//	<dir>/<kind>/<sha256(addr)[:16]>.json
type Store struct {
	Dir string
}

func (s *Store) path(kind, addr string) string {
	h := sha256.Sum256([]byte(strings.ToLower(addr)))
	return filepath.Join(s.Dir, kind, hex.EncodeToString(h[:16])+".json")
}

// Get loads the record for (kind, addr) into v. It reports false if none exists.
func (s *Store) Get(kind, addr string, v any) (bool, error) {
	b, err := os.ReadFile(s.path(kind, addr))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

// Put writes v as the record for (kind, addr).
func (s *Store) Put(kind, addr string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	p := s.path(kind, addr)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Update loads the record for (kind, addr) into v, calls fn, and writes v back
// if fn returns true, holding an exclusive lock on kind throughout.
func (s *Store) Update(kind, addr string, v any, fn func(exists bool) bool) error {
	dir := filepath.Join(s.Dir, kind)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	exists, err := s.Get(kind, addr, v)
	if err != nil {
		return err
	}
	if !fn(exists) {
		return nil
	}
	return s.Put(kind, addr, v)
}
