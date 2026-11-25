package redir

import (
	"net/netip"
	"testing"
)

func TestTProxyReplyBind(t *testing.T) {
	for destination, want := range map[string]string{
		"192.168.1.1":        "192.0.0.8",
		"::ffff:192.168.1.1": "192.0.0.8",
		"fd00::1":            "100::1",
		"fe80::1":            "100::1",
	} {
		if got := TProxyReplyBind(netip.MustParseAddr(destination)); got != netip.MustParseAddr(want) {
			t.Errorf("%s: %s, ожидался %s", destination, got, want)
		}
	}
}
