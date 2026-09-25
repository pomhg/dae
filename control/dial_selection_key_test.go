/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

func TestDialerSelectionKey(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		dst    string
		want   string
	}{
		{name: "destination IP fallback", dst: "192.0.2.1:443", want: "192.0.2.1"},
		{name: "normalized domain", domain: "Example.COM.", dst: "192.0.2.1:443", want: "example.com"},
		{name: "domain with port", domain: "Example.COM:8443", dst: "192.0.2.1:443", want: "example.com"},
		{name: "bracketed IPv6", domain: "[2001:db8::1]", dst: "[2001:db8::2]:443", want: "2001:db8::1"},
		{name: "IPv6 with port", domain: "[2001:db8::1]:8443", dst: "[2001:db8::2]:443", want: "2001:db8::1"},
		{name: "mapped IPv4", domain: "::ffff:192.0.2.1", dst: "[2001:db8::2]:443", want: "192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := netip.MustParseAddrPort(tt.dst)
			if got := dialerSelectionKey(tt.domain, dst); got != tt.want {
				t.Fatalf("dialerSelectionKey(%q, %v) = %q, want %q", tt.domain, dst, got, tt.want)
			}
		})
	}
}
