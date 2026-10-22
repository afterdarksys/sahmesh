package target

import "testing"

func TestCheck(t *testing.T) {
	ok := []string{"local", "10.0.0.7", "192.168.1.9", "8.8.8.8", "2001:db8::1"}
	for _, h := range ok {
		if err := Check(h); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
	}
	bad := []string{
		"", "localhost", "example.com", "web1", "127.0.0.1", "127.0.0.2", "::1",
		"[::1]", "10.0.0.7%eth0", "fe80::1%eth0", "::ffff:127.0.0.1", "Local",
		"metadata.google.internal", "metadata.goog",
	}
	for _, h := range bad {
		err := Check(h)
		if err == nil || err.Error() != CodeBad {
			t.Fatalf("%s: got %v, want bad_target", h, err)
		}
	}
	forbidden := []string{
		"0.0.0.0", "0.1.2.3", "::", "169.254.169.254", "169.254.1.1",
		"224.0.0.1", "239.255.255.255", "255.255.255.255", "240.0.0.1",
		"100.100.100.200", "fd00:ec2::254", "fe80::1", "ff02::1",
		"::ffff:169.254.169.254",
	}
	for _, h := range forbidden {
		err := Check(h)
		if err == nil || err.Error() != CodeForbidden {
			t.Fatalf("%s: got %v, want target_forbidden", h, err)
		}
	}
}
