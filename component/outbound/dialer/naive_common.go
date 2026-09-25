/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sagernet/sing/common/uot"
)

const naiveScheme = "naive"

type naiveLinkOptions struct {
	name                  string
	quic                  bool
	server                string
	port                  uint16
	username              string
	password              string
	serverName            string
	allowInsecure         bool
	insecureConcurrency   int
	uotEnabled            bool
	uotVersion            uint8
	quicCongestionControl string
	extraHeaders          map[string]string
}

func init() {
	D.FromLinkRegister(naiveScheme, newCronetNaive)
}

func parseNaiveLink(link string) (*naiveLinkOptions, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", D.InvalidParameterErr, err)
	}
	if u.Scheme != naiveScheme {
		return nil, fmt.Errorf("%w: unsupported scheme %q", D.InvalidParameterErr, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: missing host", D.InvalidParameterErr)
	}
	port := uint64(443)
	if rawPort := u.Port(); rawPort != "" {
		port, err = strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("%w: invalid port %q", D.InvalidParameterErr, rawPort)
		}
	}

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	query := u.Query()
	mode := strings.ToLower(query.Get("mode"))
	var quic bool
	switch mode {
	case "":
	case "quic":
		quic = true
	default:
		return nil, fmt.Errorf("%w: unsupported naive mode %q", D.InvalidParameterErr, mode)
	}

	serverName := firstQueryValue(query, "sni", "server_name", "serverName")
	if serverName == "" {
		serverName = host
	}

	allowInsecure, err := parseOptionalBool(query, false, "allowInsecure", "allow_insecure", "allowinsecure", "skipVerify")
	if err != nil {
		return nil, err
	}
	uotEnabled, err := parseOptionalBool(query, true, "uot", "udpOverTcp", "udp_over_tcp")
	if err != nil {
		return nil, err
	}

	uotVersion := uint64(uot.Version)
	if rawVersion := firstQueryValue(query, "uotVersion", "uot_version"); rawVersion != "" {
		uotVersion, err = strconv.ParseUint(rawVersion, 10, 8)
		if err != nil || (uotVersion != uot.LegacyVersion && uotVersion != uot.Version) {
			return nil, fmt.Errorf("%w: unsupported UoT version %q", D.InvalidParameterErr, rawVersion)
		}
	}

	insecureConcurrency := 0
	if rawConcurrency := firstQueryValue(query, "insecureConcurrency", "insecure_concurrency"); rawConcurrency != "" {
		insecureConcurrency, err = strconv.Atoi(rawConcurrency)
		if err != nil || insecureConcurrency < 1 {
			return nil, fmt.Errorf("%w: invalid insecure concurrency %q", D.InvalidParameterErr, rawConcurrency)
		}
	}

	quicCongestionControl := strings.ToLower(firstQueryValue(query, "quicCongestionControl", "quic_congestion_control"))
	switch quicCongestionControl {
	case "", "bbr", "bbr2", "cubic", "reno":
	default:
		return nil, fmt.Errorf("%w: unsupported QUIC congestion control %q", D.InvalidParameterErr, quicCongestionControl)
	}

	extraHeaders := make(map[string]string)
	for key, values := range query {
		headerName, ok := strings.CutPrefix(key, "header.")
		if !ok || headerName == "" || len(values) == 0 {
			continue
		}
		extraHeaders[headerName] = values[0]
	}

	return &naiveLinkOptions{
		name:                  u.Fragment,
		quic:                  quic,
		server:                host,
		port:                  uint16(port),
		username:              username,
		password:              password,
		serverName:            serverName,
		allowInsecure:         allowInsecure,
		insecureConcurrency:   insecureConcurrency,
		uotEnabled:            uotEnabled,
		uotVersion:            uint8(uotVersion),
		quicCongestionControl: quicCongestionControl,
		extraHeaders:          extraHeaders,
	}, nil
}

func (o *naiveLinkOptions) address() string {
	return net.JoinHostPort(o.server, strconv.Itoa(int(o.port)))
}

func (o *naiveLinkOptions) property(link string) *D.Property {
	return &D.Property{
		Name:     o.name,
		Address:  o.address(),
		Protocol: naiveScheme,
		Link:     link,
	}
}

func firstQueryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func parseOptionalBool(query url.Values, defaultValue bool, keys ...string) (bool, error) {
	for _, key := range keys {
		values, loaded := query[key]
		if !loaded || len(values) == 0 {
			continue
		}
		value, err := strconv.ParseBool(values[0])
		if err != nil {
			return false, fmt.Errorf("%w: invalid boolean %s=%q", D.InvalidParameterErr, key, values[0])
		}
		return value, nil
	}
	return defaultValue, nil
}
