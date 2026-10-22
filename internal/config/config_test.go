package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/afterdarksys/sahmesh/internal/secfile"
)

func envMap(m map[string]string) Env { return func(k string) string { return m[k] } }

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultsWithoutFile(t *testing.T) {
	xdg := t.TempDir()
	cfg, err := Load(envMap(map[string]string{"XDG_CONFIG_HOME": xdg}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != "" || cfg.SystemAPIURL != "" || cfg.APIKey != "" {
		t.Fatalf("unexpected %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.Methods, []string{"agent"}) {
		t.Fatalf("methods %v", cfg.Methods)
	}
	if cfg.TokenFile != filepath.Join(xdg, "sahconnect", "token") {
		t.Fatalf("token file %s", cfg.TokenFile)
	}
	home := t.TempDir()
	cfg, err = Load(envMap(map[string]string{"HOME": home}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TokenFile != filepath.Join(home, ".config", "sahconnect", "token") {
		t.Fatalf("home token file %s", cfg.TokenFile)
	}
	if _, err := Load(envMap(map[string]string{"XDG_CONFIG_HOME": "relative"})); err == nil {
		t.Fatal("relative XDG_CONFIG_HOME accepted")
	}
}

func TestFileAndEnvPrecedence(t *testing.T) {
	xdg := t.TempDir()
	home := t.TempDir()
	write(t, filepath.Join(xdg, "sahconnect", "config.toml"), `
systemapi_url = "https://file.example"
method = "agent,ssh"
token_file = "~/tok/bearer"
`, 0o600)
	env := map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home}
	cfg, err := Load(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SystemAPIURL != "https://file.example" {
		t.Fatalf("url %s", cfg.SystemAPIURL)
	}
	if !reflect.DeepEqual(cfg.Methods, []string{"agent", "ssh"}) {
		t.Fatalf("methods %v", cfg.Methods)
	}
	if cfg.TokenFile != filepath.Join(home, "tok", "bearer") {
		t.Fatalf("token %s", cfg.TokenFile)
	}
	env["SYSTEMAPI_URL"] = "https://env.example"
	env["SYSTEMAPI_API_KEY"] = "k"
	cfg, err = Load(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SystemAPIURL != "https://env.example" || cfg.APIKey != "k" {
		t.Fatalf("env override %+v", cfg)
	}
	// SAHCONNECT_CONFIG beats the XDG path, and must exist.
	other := filepath.Join(t.TempDir(), "other.toml")
	write(t, other, `systemapi_url = "https://other.example"`+"\nmethod = [\"agent\"]\n", 0o644)
	delete(env, "SYSTEMAPI_URL")
	env["SAHCONNECT_CONFIG"] = other
	cfg, err = Load(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SystemAPIURL != "https://other.example" || cfg.Path != other {
		t.Fatalf("explicit %+v", cfg)
	}
	env["SAHCONNECT_CONFIG"] = other + ".missing"
	if _, err := Load(envMap(env)); err == nil {
		t.Fatal("missing explicit config accepted")
	}
}

func TestInsecurePermissionsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666, 0o777} {
		p := filepath.Join(t.TempDir(), "c.toml")
		write(t, p, `systemapi_url = "https://evil.example"`, mode)
		_, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": p, "HOME": t.TempDir()}))
		if err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("mode %o accepted: %v", mode, err)
		}
	}
	dir := t.TempDir()
	if _, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": dir, "HOME": dir})); err == nil {
		t.Fatal("directory accepted as config")
	}
}

func TestUnknownKeysAndBadValuesRefused(t *testing.T) {
	cases := map[string]string{
		"unknown":    `systemapi_ulr = "https://x.example"`,
		"badmethod":  `method = ["agent","telnet"]`,
		"dup":        `method = "agent,agent"`,
		"empty":      `method = ""`,
		"emptyarray": `method = []`,
		"int":        `method = 3`,
		"relative":   `token_file = "tok"`,
		"syntax":     `systemapi_url = `,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), "c.toml")
		write(t, p, body, 0o600)
		if _, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": p, "HOME": t.TempDir()})); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestParseMethods(t *testing.T) {
	good := map[string][]string{
		"agent":        {"agent"},
		"ssh":          {"ssh"},
		"agent,ssh":    {"agent", "ssh"},
		" SSH , agent": {"ssh", "agent"},
	}
	for in, want := range good {
		got, err := ParseMethods([]string{in})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "agent,", "mosh", "agent,agent"} {
		if _, err := ParseMethods([]string{in}); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestSymlinkForeignOwnerAndParentRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.toml")
	write(t, real, `systemapi_url = "https://cp.example"`, 0o600)
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": link, "HOME": dir})); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink config: %v", err)
	}
	secfile.CurrentUID = func() int { return os.Getuid() + 4242 }
	t.Cleanup(func() { secfile.CurrentUID = os.Getuid })
	_, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": real, "HOME": dir}))
	secfile.CurrentUID = os.Getuid
	if err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("foreign config: %v", err)
	}
	shared := filepath.Join(t.TempDir(), "shared")
	write(t, filepath.Join(shared, "c.toml"), `systemapi_url = "https://cp.example"`, 0o600)
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": filepath.Join(shared, "c.toml"), "HOME": dir})); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable parent: %v", err)
	}
}

func TestTokenFileMustStayHome(t *testing.T) {
	home := t.TempDir()
	for _, tf := range []string{"/etc/sahconnect-token", "~/../elsewhere", home, "~"} {
		p := filepath.Join(t.TempDir(), "c.toml")
		write(t, p, `token_file = "`+tf+`"`, 0o600)
		if _, err := Load(envMap(map[string]string{"SAHCONNECT_CONFIG": p, "HOME": home})); err == nil {
			t.Fatalf("token_file %s accepted", tf)
		}
	}
}
