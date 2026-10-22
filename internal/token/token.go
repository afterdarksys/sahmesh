// Package token stores the device-login bearer token together with the
// control-plane origin that issued it.
//
// Threats:
//   - A bearer sent to the wrong server is a stolen session. The file binds
//     the token to its issuing origin (scheme://host[:port]) and callers must
//     refuse to send it anywhere else.
//   - The bearer is a session for its TTL (one hour server side). It is
//     written 0600 in a 0700 directory owned by the user, atomically (temp
//     file, fsync, rename), so a crash never leaves a partial or readable
//     token.
//   - Another local user swapping in a symlink or their own file: Read opens
//     with O_NOFOLLOW and checks the open descriptor (regular, owned by the
//     user, no group or other bits) and the directory (owned, 0700).
//   - A mistyped token_file (say ~/.ssh/id_ed25519): Write and Delete replace
//     or remove an existing file only if it is a valid token file, so a key
//     can never be clobbered or deleted.
//   - The token is never printed; callers show Fingerprint.
//
// Does NOT encrypt the token at rest, and does NOT protect it from the
// account's own user or root.
package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/sahmesh/internal/secfile"
)

// MaxLen bounds a token.
const MaxLen = 512

const maxFile = 2048

// File is the stored credential.
type File struct {
	Origin string // canonical scheme://host[:port]
	Token  string
}

type fileJSON struct {
	V      int    `json:"v"`
	Origin string `json:"origin"`
	Token  string `json:"token"`
}

// Valid reports whether s is a plausible opaque bearer: 16-512 printable
// ASCII characters with no whitespace.
func Valid(s string) bool {
	if len(s) < 16 || len(s) > MaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Fingerprint is the first 16 hex characters of SHA-256(token): safe to show.
func Fingerprint(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])[:16]
}

// Origin is the canonical origin of u: lower-case scheme and host, default
// port (443 for https, 80 for http) dropped. "" when u is not http(s).
func Origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]"
	}
	return scheme + "://" + host
}

func validOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && Origin(u) == o
}

func parse(b []byte) (*File, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j fileJSON
	if err := dec.Decode(&j); err != nil || dec.More() {
		return nil, errors.New("not a sahconnect token file")
	}
	if j.V != 1 || !validOrigin(j.Origin) || !Valid(j.Token) {
		return nil, errors.New("not a sahconnect token file")
	}
	return &File{Origin: j.Origin, Token: j.Token}, nil
}

// checkDir requires the token directory to be a real directory owned by the
// user with no group or other permissions.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("token directory %s is not a directory (symlinks are refused)", dir)
	}
	if !secfile.OwnedBy(fi, false) {
		return fmt.Errorf("token directory %s is owned by another user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("token directory %s must be mode 0700 (chmod 700 it)", dir)
	}
	return nil
}

// readAt opens path without following symlinks and parses it. found is false
// when nothing exists at path.
func readAt(path string) (f *File, found bool, err error) {
	fh, fi, err := secfile.OpenNoFollow(path, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("token file: %w", err)
	}
	defer fh.Close()
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, true, fmt.Errorf("token file %s is readable or writable by others (remove it and run sahconnect login)", path)
	}
	if fi.Size() > maxFile {
		return nil, true, fmt.Errorf("token file %s is not a sahconnect token file", path)
	}
	b, err := io.ReadAll(io.LimitReader(fh, maxFile+1))
	if err != nil {
		return nil, true, fmt.Errorf("token file: %w", err)
	}
	tf, perr := parse(b)
	if perr != nil && Valid(strings.TrimSuffix(string(b), "\n")) {
		return nil, true, fmt.Errorf("token file %s is in an old format; delete %s by hand, then run sahconnect login", path, path)
	}
	if perr != nil {
		return nil, true, fmt.Errorf("token file %s is not a sahconnect token file (run sahconnect login, or fix token_file)", path)
	}
	return tf, true, nil
}

// Read returns the stored credential. found is false when no file exists.
// Anything else that is wrong is an error: the caller must not fall back.
func Read(path string) (*File, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, true, err
	}
	return readAt(path)
}

// Write stores the token for origin at path, mode 0600, atomically. A missing
// directory is created 0700. An existing directory is tightened to 0700 only
// when it is managedDir (sahconnect's own config directory); any other
// directory that is not already 0700 is refused, so a token_file in $HOME
// never chmods $HOME. An existing file is replaced only when it is a valid
// token file.
func Write(path, origin, tok, managedDir string) error {
	if !filepath.IsAbs(path) {
		return errors.New("token file path must be absolute")
	}
	if !validOrigin(origin) || !Valid(tok) {
		return errors.New("token rejected")
	}
	dir := filepath.Dir(path)
	_, statErr := os.Lstat(dir)
	created := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	if !fi.IsDir() || !secfile.OwnedBy(fi, false) {
		return fmt.Errorf("token directory %s is not a directory owned by you", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if !created && (managedDir == "" || filepath.Clean(managedDir) != dir) {
			return fmt.Errorf("token directory %s is mode %04o, not 0700: chmod 700 %s or move token_file", dir, fi.Mode().Perm(), dir)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("token directory: %w", err)
		}
	}
	if err := checkDir(dir); err != nil {
		return err
	}
	// Replace only a valid token file (or nothing).
	if _, _, err := readAt(path); err != nil {
		return fmt.Errorf("refusing to replace %s: %w", path, err)
	}
	body, err := json.Marshal(fileJSON{V: 1, Origin: origin, Token: tok})
	if err != nil {
		return errors.New("token rejected")
	}
	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: persist the rename; the token is already in place
		_ = d.Close()
	}
	return nil
}

// Delete removes the token file. removed is false when there was none. A file
// that is not a valid token file is refused, never removed.
func Delete(path string) (removed bool, err error) {
	if _, found, err := readAt(path); err != nil {
		return false, fmt.Errorf("refusing to delete %s: %w", path, err)
	} else if !found {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("token file: %w", err)
	}
	return true, nil
}
