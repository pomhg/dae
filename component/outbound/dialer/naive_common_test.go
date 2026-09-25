/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"testing"

	"github.com/sagernet/sing/common/uot"
)

func TestParseNaiveLink(t *testing.T) {
	tests := []struct {
		name            string
		link            string
		wantErr         bool
		wantQUIC        bool
		wantAddress     string
		wantServerName  string
		wantUser        string
		wantPassword    string
		wantUOT         bool
		wantUOTVersion  uint8
		wantConcurrency int
		wantHeader      string
	}{
		{
			name:           "https defaults to UoT v2",
			link:           "naive://user:pass@example.com#node",
			wantAddress:    "example.com:443",
			wantServerName: "example.com",
			wantUser:       "user",
			wantPassword:   "pass",
			wantUOT:        true,
			wantUOTVersion: uot.Version,
		},
		{
			name:            "quic options",
			link:            "naive://u:p@192.0.2.1:8443?mode=quic&sni=proxy.example&uot_version=1&insecure_concurrency=2&quic_congestion_control=bbr2&header.X-Test=yes",
			wantQUIC:        true,
			wantAddress:     "192.0.2.1:8443",
			wantServerName:  "proxy.example",
			wantUser:        "u",
			wantPassword:    "p",
			wantUOT:         true,
			wantUOTVersion:  uot.LegacyVersion,
			wantConcurrency: 2,
			wantHeader:      "yes",
		},
		{
			name:           "disable UoT",
			link:           "naive://example.com?uot=false",
			wantAddress:    "example.com:443",
			wantServerName: "example.com",
			wantUOT:        false,
			wantUOTVersion: uot.Version,
		},
		{name: "unsupported scheme", link: "https://example.com", wantErr: true},
		{name: "legacy https scheme", link: "naive+https://example.com", wantErr: true},
		{name: "legacy quic scheme", link: "naive+quic://example.com", wantErr: true},
		{name: "missing host", link: "naive:///missing", wantErr: true},
		{name: "invalid port", link: "naive://example.com:0", wantErr: true},
		{name: "invalid mode", link: "naive://example.com?mode=https", wantErr: true},
		{name: "invalid UoT boolean", link: "naive://example.com?uot=sometimes", wantErr: true},
		{name: "invalid UoT version", link: "naive://example.com?uot_version=3", wantErr: true},
		{name: "invalid concurrency", link: "naive://example.com?insecure_concurrency=0", wantErr: true},
		{name: "invalid congestion control", link: "naive://example.com?mode=quic&quic_congestion_control=westwood", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseNaiveLink(test.link)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if options.quic != test.wantQUIC {
				t.Fatalf("QUIC = %v, want %v", options.quic, test.wantQUIC)
			}
			if protocol := options.property(test.link).Protocol; protocol != naiveScheme {
				t.Fatalf("protocol = %q, want %q", protocol, naiveScheme)
			}
			if options.address() != test.wantAddress {
				t.Fatalf("address = %q, want %q", options.address(), test.wantAddress)
			}
			if options.serverName != test.wantServerName {
				t.Fatalf("server name = %q, want %q", options.serverName, test.wantServerName)
			}
			if options.username != test.wantUser || options.password != test.wantPassword {
				t.Fatalf("credentials = %q:%q, want %q:%q", options.username, options.password, test.wantUser, test.wantPassword)
			}
			if options.uotEnabled != test.wantUOT || options.uotVersion != test.wantUOTVersion {
				t.Fatalf("UoT = %v/v%d, want %v/v%d", options.uotEnabled, options.uotVersion, test.wantUOT, test.wantUOTVersion)
			}
			if options.insecureConcurrency != test.wantConcurrency {
				t.Fatalf("insecure concurrency = %d, want %d", options.insecureConcurrency, test.wantConcurrency)
			}
			if options.extraHeaders["X-Test"] != test.wantHeader {
				t.Fatalf("X-Test header = %q, want %q", options.extraHeaders["X-Test"], test.wantHeader)
			}
		})
	}
}
