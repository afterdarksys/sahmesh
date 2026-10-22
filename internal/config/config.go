// Package config loads sahconnect's client configuration.
//
// Threats: a config file another local user can write could point sahconnect
// at a hostile control plane or redirect the token file. The file is opened
// with O_NOFOLLOW and checked on the open descriptor: it must be a regular
// file owned by the current user (or root), not group- or world-writable, in
// a directory that is not group- or world-writable. token_file must lie
// inside the home or the sahconnect config directory. Unknown
// keys are refused so a typo cannot silently drop a setting. The file holds
// no secret: the API key comes only from the environment and the bearer only
// from the token file. Does NOT protect against a user who controls the
// account's own home directory or environment.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/afterdarksys/sahmesh/internal/secfile"
)

// Methods.
const (
	MethodAgent = "agent"
	MethodSSH   = "ssh"
)

// Config is the effective configuration after environment overrides.
type Config struct {
	Path         string   // the config file consulted ("" when none exists)
	SystemAPIURL string   // unvalidated; client.ValidateBase checks it
	Methods      []string // ordered preference, each agent or ssh
	TokenFile    string   // absolute
	APIKey       string   // SYSTEMAPI_API_KEY only
}

// Methods is the TOML value of `method`: an array of strings, or one string
// holding a comma-separated list.
type Methods []string

// UnmarshalTOML accepts ["agent","ssh"] or "agent,ssh".
func (m *Methods) UnmarshalTOML(v any) error {
	var parts []string
	switch t := v.(type) {
	case string:
		parts = strings.Split(t, ",")
	case []any:
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return errors.New("method: entries must be strings")
			}
			parts = append(parts, strings.Split(s, ",")...)
		}
	default:
		return errors.New("method: must be a string or an array of strings")
	}
	out, err := ParseMethods(parts)
	if err != nil {
		return err
	}
	*m = out
	return nil
}

// ParseMethods validates an ordered method list: non-empty, each agent or ssh,
// no duplicates. Entries may themselves hold comma-separated lists.
func ParseMethods(parts []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range parts {
		for _, p := range strings.Split(raw, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p != MethodAgent && p != MethodSSH {
				return nil, fmt.Errorf("method: %q is not agent or ssh", p)
			}
			if seen[p] {
				return nil, fmt.Errorf("method: %q listed twice", p)
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("method: empty")
	}
	return out, nil
}

type file struct {
	SystemAPIURL string  `toml:"systemapi_url"`
	Method       Methods `toml:"method"`
	TokenFile    string  `toml:"token_file"`
}

// Env abstracts os.Getenv for tests.
type Env func(string) string

// Dir is the sahconnect config directory: $XDG_CONFIG_HOME/sahconnect, else
// ~/.config/sahconnect.
func Dir(env Env) (string, error) {
	if x := env("XDG_CONFIG_HOME"); x != "" {
		if !filepath.IsAbs(x) {
			return "", errors.New("XDG_CONFIG_HOME must be absolute")
		}
		return filepath.Join(x, "sahconnect"), nil
	}
	home, err := homeDir(env)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sahconnect"), nil
}

// Load reads the config file and applies environment overrides. The file is
// SAHCONNECT_CONFIG when set (it must exist), else Dir()/config.toml (absent
// is fine). SYSTEMAPI_URL overrides systemapi_url.
func Load(env Env) (*Config, error) {
	dir, err := Dir(env)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		Methods:   []string{MethodAgent},
		TokenFile: filepath.Join(dir, "token"),
	}
	path := env("SAHCONNECT_CONFIG")
	explicit := path != ""
	if !explicit {
		path = filepath.Join(dir, "config.toml")
	}
	var f file
	if err := readFile(path, &f); err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			path = ""
		} else {
			return nil, err
		}
	}
	cfg.Path = path
	if f.SystemAPIURL != "" {
		cfg.SystemAPIURL = f.SystemAPIURL
	}
	if len(f.Method) > 0 {
		cfg.Methods = f.Method
	}
	if f.TokenFile != "" {
		tf, err := expandHome(f.TokenFile, env)
		if err != nil {
			return nil, err
		}
		home, herr := homeDir(env)
		if herr != nil || !(within(tf, home) || within(tf, dir)) {
			return nil, fmt.Errorf("token_file %s: must be inside the home or sahconnect config directory", tf)
		}
		cfg.TokenFile = tf
	}
	if v := env("SYSTEMAPI_URL"); v != "" {
		cfg.SystemAPIURL = v
	}
	cfg.APIKey = env("SYSTEMAPI_API_KEY")
	return cfg, nil
}

func readFile(path string, f *file) error {
	fh, st, err := secfile.OpenNoFollow(path, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fmt.Errorf("config: %w", err)
	}
	defer fh.Close()
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config %s: refusing a group- or world-writable file (chmod go-w)", path)
	}
	if st.Size() > 64<<10 {
		return fmt.Errorf("config %s: larger than 64 KiB", path)
	}
	if _, err := secfile.CheckDir(filepath.Dir(path), true); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	md, err := toml.NewDecoder(io.LimitReader(fh, 64<<10)).Decode(f)
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, 0, len(und))
		for _, k := range und {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return fmt.Errorf("config %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	return nil
}

func homeDir(env Env) (string, error) {
	if h := env("HOME"); h != "" {
		return h, nil
	}
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "", errors.New("cannot find the home directory")
	}
	return h, nil
}

// within reports whether p is strictly inside root.
func within(p, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func expandHome(p string, env Env) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := homeDir(env)
		if err != nil {
			return "", errors.New("token_file: cannot expand ~")
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("token_file: must be an absolute path or start with ~/")
	}
	return filepath.Clean(p), nil
}
