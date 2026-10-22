package secfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenNoFollow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _, err := OpenNoFollow(p, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	link := filepath.Join(dir, "l")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenNoFollow(link, false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	if _, _, err := OpenNoFollow(dir, false); err == nil {
		t.Fatal("directory accepted")
	}
	CurrentUID = func() int { return os.Getuid() + 4242 }
	defer func() { CurrentUID = os.Getuid }()
	if _, _, err := OpenNoFollow(p, false); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("foreign owner: %v", err)
	}
	if _, err := CheckDir(dir, false); err == nil {
		t.Fatal("foreign dir accepted")
	}
	if _, _, err := OpenNoFollow(filepath.Join(dir, "missing"), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestCheckDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := CheckDir(dir, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDir(dir, false); err == nil {
		t.Fatal("world-writable dir accepted")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "l")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDir(link, false); err == nil {
		t.Fatal("symlinked dir accepted")
	}
}
