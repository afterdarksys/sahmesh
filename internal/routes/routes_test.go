package routes

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afterdarksys/sahmesh/internal/secfile"
)

func TestParseFlagAndLookup(t *testing.T) {
	tb := New()
	for _, f := range []string{"10.0.0.0/8=core", "10.0.1.0/24=edge", "2001:db8::/32=v6gw", "192.168.1.5/32=one"} {
		if err := tb.AddFlag(f); err != nil {
			t.Fatal(f, err)
		}
	}
	cases := map[string]string{
		"10.0.1.7":        "edge",
		"10.9.9.9":        "core",
		"2001:db8::1":     "v6gw",
		"::ffff:10.0.1.7": "edge", // IPv4-mapped normalizes
		"192.168.1.5":     "one",
		"192.168.1.6":     "",
		"172.16.0.1":      "",
		"2001:db9::1":     "",
	}
	for ip, want := range cases {
		via, ok := tb.Lookup(netip.MustParseAddr(ip))
		if (want == "") == ok || via != want {
			t.Fatalf("%s: got %q %v want %q", ip, via, ok, want)
		}
	}
	if tb.Len() != 4 {
		t.Fatal("len")
	}
}

func TestAddRefusals(t *testing.T) {
	tb := New()
	bad := map[string]string{
		"10.0.0.0/8":          "bad_route",
		"=gw":                 "bad_route",
		"10.0.0.0/8=":         "bad_route",
		"10.0.0.0/8=bad host": "bad_route",
		"10.0.0.0/8=../x":     "bad_route",
		"10.0.0.1/8=gw":       "bad_route", // host bits set
		"10.0.0.0/33=gw":      "bad_route",
		"example.com/8=gw":    "bad_route",
		"10.0.0.0/8=gw=extra": "bad_route",
		"fe80::/10=gw":        "bad_route", // refused classes never route
		"127.0.0.0/8=gw":      "bad_route",
		"169.254.0.0/16=gw":   "bad_route",
		"0.0.0.0/0=gw":        "bad_route",
		"::/0=gw":             "bad_route",
	}
	for f, code := range bad {
		err := tb.AddFlag(f)
		if err == nil || err.Error() != code {
			t.Fatalf("%q: got %v want %s", f, err, code)
		}
	}
	if err := tb.AddFlag("10.0.0.0/8=gw"); err != nil {
		t.Fatal(err)
	}
	if err := tb.AddFlag("10.0.0.0/8=other"); err == nil || err.Error() != "duplicate_route" {
		t.Fatalf("duplicate: %v", err)
	}
	if tb.Len() != 1 {
		t.Fatal("duplicate added")
	}
}

func writeFile(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	good := writeFile(t, dir, "routes.toml", "[[route]]\ncidr = \"10.0.0.0/24\"\nvia = \"gw1\"\n\n[[route]]\ncidr = \"10.1.0.0/16\"\nvia = \"gw2\"\n", 0o600)
	tb := New()
	if err := tb.LoadFile(good); err != nil {
		t.Fatal(err)
	}
	if via, _ := tb.Lookup(netip.MustParseAddr("10.0.0.9")); via != "gw1" {
		t.Fatal("file route")
	}
	// A flag and the file may both be given; a duplicate across them is refused.
	if err := tb.AddFlag("10.0.0.0/24=gw9"); err == nil || err.Error() != "duplicate_route" {
		t.Fatal("cross duplicate")
	}
	// Missing file is fine.
	if err := New().LoadFile(filepath.Join(dir, "absent.toml")); err != nil {
		t.Fatalf("missing: %v", err)
	}
	// Unknown key refused.
	unk := writeFile(t, dir, "unk.toml", "[[route]]\ncidr = \"10.0.0.0/24\"\nvia = \"gw1\"\nextra = 1\n", 0o600)
	if err := New().LoadFile(unk); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("unknown key: %v", err)
	}
	// Bad route inside the file refused.
	badr := writeFile(t, dir, "bad.toml", "[[route]]\ncidr = \"127.0.0.0/8\"\nvia = \"gw1\"\n", 0o600)
	if err := New().LoadFile(badr); err == nil || err.Error() != "bad_route" {
		t.Fatalf("bad route: %v", err)
	}
	// World-writable refused.
	ww := writeFile(t, dir, "ww.toml", "[[route]]\ncidr = \"10.0.0.0/24\"\nvia = \"gw1\"\n", 0o666)
	if err := New().LoadFile(ww); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("world-writable: %v", err)
	}
	// Symlink refused.
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := New().LoadFile(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	// Another owner refused.
	old := secfile.CurrentUID
	secfile.CurrentUID = func() int { return os.Getuid() + 1 }
	err := New().LoadFile(good)
	secfile.CurrentUID = old
	if err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("owner: %v", err)
	}
	// World-writable parent directory refused.
	wdir := filepath.Join(dir, "open")
	if err := os.Mkdir(wdir, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(wdir, 0o777)
	inOpen := writeFile(t, wdir, "routes.toml", "[[route]]\ncidr = \"10.0.0.0/24\"\nvia = \"gw1\"\n", 0o600)
	if err := New().LoadFile(inOpen); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("open dir: %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	env := func(k string) string {
		switch k {
		case "XDG_CONFIG_HOME":
			return "/xdg"
		case "HOME":
			return "/home/u"
		}
		return ""
	}
	if p, _ := DefaultPath(env); p != "/xdg/sahmesh/routes.toml" {
		t.Fatal(p)
	}
	env2 := func(k string) string {
		if k == "HOME" {
			return "/home/u"
		}
		return ""
	}
	if p, _ := DefaultPath(env2); p != "/home/u/.config/sahmesh/routes.toml" {
		t.Fatal(p)
	}
	if _, err := DefaultPath(func(k string) string {
		if k == "XDG_CONFIG_HOME" {
			return "relative"
		}
		return ""
	}); err == nil {
		t.Fatal("relative xdg")
	}
}
