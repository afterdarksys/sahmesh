package token

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahmesh/internal/secfile"
)

const (
	secret = "SENTINEL-TOKEN-0123456789abcdef"
	origin = "https://cp.example"
)

func privDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "sahconnect")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestWriteIsPrivateAtomicAndBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg", "sahconnect")
	path := filepath.Join(dir, "token")
	if err := Write(path, origin, secret, ""); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %o", st.Mode().Perm())
	}
	if dst, _ := os.Stat(dir); dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dst.Mode().Perm())
	}
	got, found, err := Read(path)
	if err != nil || !found || got.Token != secret || got.Origin != origin {
		t.Fatalf("read %+v %v %v", got, found, err)
	}
	before, _ := os.Stat(path)
	if err := Write(path, origin, secret+"X", ""); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if os.SameFile(before, after) {
		t.Fatal("overwrite was in place, not an atomic rename")
	}
	if err := Write(path, origin, "short", ""); err == nil {
		t.Fatal("invalid token written")
	}
	if err := Write(path, "https://cp.example/path", secret, ""); err == nil {
		t.Fatal("non-origin accepted")
	}
	got, _, _ = Read(path)
	if got.Token != secret+"X" {
		t.Fatal("failed write clobbered the token")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
}

func TestOrigin(t *testing.T) {
	cases := map[string]string{
		"https://CP.example:443":  "https://cp.example",
		"https://cp.example.":     "https://cp.example",
		"https://cp.example:8443": "https://cp.example:8443",
		"http://127.0.0.1:80":     "http://127.0.0.1",
		"http://[::1]:3003":       "http://[::1]:3003",
		"ftp://cp.example":        "",
	}
	for in, want := range cases {
		u, _ := url.Parse(in)
		if got := Origin(u); got != want {
			t.Fatalf("%s: %q want %q", in, got, want)
		}
	}
}

func TestDirTightenedOrRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Not sahconnect's directory: refused, mode untouched.
	if err := Write(filepath.Join(dir, "token"), origin, secret, ""); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("unmanaged loose dir: %v", err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
		t.Fatalf("unmanaged dir mode changed: %o", st.Mode().Perm())
	}
	// sahconnect's own config dir: tightened.
	if err := Write(filepath.Join(dir, "token"), origin, secret, dir); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir not tightened: %o", st.Mode().Perm())
	}
	// A loose directory is refused at Read rather than silently trusted.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(filepath.Join(dir, "token")); err == nil {
		t.Fatal("loose dir accepted at read")
	}
	secfile.CurrentUID = func() int { return os.Getuid() + 4242 }
	defer func() { secfile.CurrentUID = os.Getuid }()
	if err := Write(filepath.Join(privDir(t), "token"), origin, secret, ""); err == nil {
		t.Fatal("foreign dir accepted")
	}
}

func TestReadRefusals(t *testing.T) {
	dir := privDir(t)
	path := filepath.Join(dir, "token")
	if err := Write(path, origin, secret, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, found, err := Read(path)
	if err == nil || !found || strings.Contains(err.Error(), secret) {
		t.Fatalf("0644 token: %v", err)
	}
	for _, body := range []string{secret, `{"v":2,"origin":"https://cp.example","token":"` + secret + `"}`,
		`{"v":1,"origin":"https://cp.example","token":"` + secret + `","x":1}`, `{"v":1,"origin":"cp.example","token":"` + secret + `"}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(path, 0o600)
		if _, _, err := Read(path); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("corrupt %q: %v", body, err)
		}
	}
}

func TestSymlinkSwappedInAtRead(t *testing.T) {
	src := privDir(t)
	target := filepath.Join(src, "token")
	if err := Write(target, origin, secret, ""); err != nil {
		t.Fatal(err)
	}
	dir := privDir(t)
	path := filepath.Join(dir, "token")
	if err := Write(path, origin, secret, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink read: %v", err)
	}
	if _, err := Delete(path); err == nil {
		t.Fatal("symlink deleted")
	}
	if err := Write(path, origin, secret, ""); err == nil {
		t.Fatal("symlink replaced")
	}
}

func TestNeverClobbersOrDeletesNonToken(t *testing.T) {
	dir := privDir(t)
	key := filepath.Join(dir, "id_ed25519")
	keyBody := "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(key, []byte(keyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(key, origin, secret, ""); err == nil {
		t.Fatal("clobbered a key file")
	}
	if removed, err := Delete(key); err == nil || removed {
		t.Fatal("deleted a key file")
	}
	if b, _ := os.ReadFile(key); string(b) != keyBody {
		t.Fatal("key file changed")
	}
}

func TestMissingAndDelete(t *testing.T) {
	path := filepath.Join(privDir(t), "token")
	if _, found, err := Read(path); found || err != nil {
		t.Fatalf("missing: %v %v", found, err)
	}
	if removed, err := Delete(path); removed || err != nil {
		t.Fatalf("delete missing: %v %v", removed, err)
	}
	if err := Write(path, origin, secret, ""); err != nil {
		t.Fatal(err)
	}
	if removed, err := Delete(path); !removed || err != nil {
		t.Fatalf("delete: %v %v", removed, err)
	}
	if strings.Contains(Fingerprint(secret), secret) || len(Fingerprint(secret)) != 16 {
		t.Fatal("fingerprint")
	}
}

func TestHomeAndOtherDirsNeverChmodded(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(home, ".config", "sahconnect")
	for _, p := range []string{filepath.Join(home, "sahconnect-token"), filepath.Join(docs, "x")} {
		err := Write(p, origin, secret, managed)
		if err == nil || !strings.Contains(err.Error(), "move token_file") {
			t.Fatalf("%s: %v", p, err)
		}
		if _, serr := os.Stat(p); !os.IsNotExist(serr) {
			t.Fatalf("%s written", p)
		}
	}
	for _, d := range []string{home, docs} {
		if st, _ := os.Stat(d); st.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode changed to %o", d, st.Mode().Perm())
		}
	}
	// A fresh managed dir is created 0700 and works.
	if err := Write(filepath.Join(managed, "token"), origin, secret, managed); err != nil {
		t.Fatal(err)
	}
}

func TestOldPlainFormatNamed(t *testing.T) {
	path := filepath.Join(privDir(t), "token")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"read":   func() error { _, _, err := Read(path); return err }(),
		"write":  Write(path, origin, secret, ""),
		"delete": func() error { _, err := Delete(path); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "old format; delete "+path+" by hand") || strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != secret+"\n" {
		t.Fatal("old token file changed")
	}
}
