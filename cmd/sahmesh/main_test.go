package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func capture(args []string) (code int, out, errs string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e, func(string) string { return "" })
	return code, o.String(), e.String()
}

func TestVersionAndHelp(t *testing.T) {
	code, out, _ := capture([]string{"version"})
	if code != 0 || out != "sahmesh "+version+"\n" {
		t.Fatalf("%d %q", code, out)
	}
	if version != "0.1.0" {
		t.Fatal(version)
	}
	for _, a := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		if code, _, errs := capture(a); code != 0 || !strings.Contains(errs, "sahmesh up") {
			t.Fatalf("%v: %d %q", a, code, errs)
		}
	}
	if code, _, errs := capture(nil); code != 2 || !strings.Contains(errs, "sahmesh up") {
		t.Fatalf("no args: %d %q", code, errs)
	}
	if code, _, errs := capture([]string{"bogus"}); code != 2 || !strings.HasPrefix(errs, "usage\n") {
		t.Fatalf("bogus: %d %q", code, errs)
	}
}

func TestUpArgRefusals(t *testing.T) {
	cases := []struct {
		args []string
		code string
	}{
		{[]string{"up", "--listen", "0.0.0.0:1080"}, "bind_refused"},
		{[]string{"up", "--listen", "localhost:1080"}, "bind_refused"},
		{[]string{"up", "--listen", "[::]:1080"}, "bind_refused"},
		{[]string{"up", "--listen"}, "usage"},
		{[]string{"up", "--route", "10.0.0.0/8"}, "bad_route"},
		{[]string{"up", "--route", "127.0.0.0/8=gw"}, "bad_route"},
		{[]string{"up", "--route", "10.0.0.0/8=gw", "--route", "10.0.0.0/8=gw2"}, "duplicate_route"},
		{[]string{"up", "--route"}, "usage"},
		{[]string{"up", "--routes"}, "usage"},
		{[]string{"up", "--bogus"}, "usage"},
		{[]string{"up", "extra"}, "usage"},
	}
	for _, tc := range cases {
		code, out, errs := capture(tc.args)
		if code != 2 || out != "" || !strings.HasPrefix(errs, tc.code+"\n") {
			t.Fatalf("%v: code %d out %q err %q", tc.args, code, out, errs)
		}
	}
}

func TestUpNeedsURL(t *testing.T) {
	// Valid flags, but no SYSTEMAPI_URL and no config: a clear message, exit 2,
	// and nothing listening.
	var o, e bytes.Buffer
	code := run([]string{"up", "--listen", "127.0.0.1:0"}, &o, &e, func(k string) string {
		if k == "HOME" {
			return "/nonexistent-home-for-sahmesh-test"
		}
		return ""
	})
	if code != 2 || !strings.Contains(e.String(), "systemapi_url is not set") || o.String() != "" {
		t.Fatalf("%d %q %q", code, o.String(), e.String())
	}
}

func TestParseOpts(t *testing.T) {
	o, err := parseUp([]string{"--listen", "[::1]:1081", "--route", "10.0.0.0/24=gw1", "--routes", "/dev/null/none"})
	if err != nil {
		t.Fatal(err)
	}
	if o.listen != "[::1]:1081" || o.routesFile != "/dev/null/none" || o.table.Len() != 1 {
		t.Fatalf("%+v", o)
	}
	d, err := parseUp(nil)
	if err != nil || d.listen != "127.0.0.1:1080" || d.routesFile != "" {
		t.Fatalf("defaults %+v %v", d, err)
	}
}

func TestStartupReleasesProbeListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	var out, errs bytes.Buffer
	configDir := t.TempDir()
	code := run([]string{"up", "--listen", addr}, &out, &errs, func(k string) string {
		if k == "XDG_CONFIG_HOME" {
			return configDir
		}
		return ""
	})
	if code != 2 || !strings.Contains(errs.String(), "systemapi_url is not set") {
		t.Fatalf("startup: %d %q", code, errs.String())
	}
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("probe listener leaked: %v", err)
	}
	_ = ln.Close()
}
