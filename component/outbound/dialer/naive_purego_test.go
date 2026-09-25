//go:build with_purego && linux && amd64

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	_ "github.com/daeuniverse/outbound/dialer/http"
	"github.com/daeuniverse/outbound/dialer/stickyip"
	"github.com/daeuniverse/outbound/netproxy"
	mDNS "github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

type naiveTestDialer struct {
	lookupNetwork string
	lookupHost    string
}

func (d *naiveTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("unexpected dial")
}

func (d *naiveTestDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.lookupNetwork = network
	d.lookupHost = host
	return []net.IPAddr{
		{IP: net.ParseIP("192.0.2.1")},
		{IP: net.ParseIP("2001:db8::1")},
	}, nil
}

func TestCronetNaiveCreationIsLazy(t *testing.T) {
	dialer, property, err := newCronetNaive(nil, &naiveTestDialer{}, "naive://user:pass@example.com#test")
	if err != nil {
		t.Fatal(err)
	}
	if property.Address != "example.com:443" || property.Protocol != naiveScheme {
		t.Fatalf("unexpected property: %+v", property)
	}
	closer := dialer.(*cronetNaiveDialer)
	if len(closer.clients) != 0 {
		t.Fatal("Cronet client was initialized during link parsing")
	}
	if err = closer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = closer.DialContext(context.Background(), "tcp", "example.net:443")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after close error = %v, want net.ErrClosed", err)
	}
}

func TestNormalizeNaiveNetwork(t *testing.T) {
	network, err := normalizeNaiveNetwork("udp6")
	if err != nil {
		t.Fatal(err)
	}
	if network.Network != "udp" || network.IPVersion != "6" {
		t.Fatalf("normalized network = %+v", network)
	}

	encoded := netproxy.MagicNetwork{Network: "tcp", Mark: 9, Mptcp: true, IPVersion: "4"}.Encode()
	network, err = normalizeNaiveNetwork(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if network.Network != "tcp" || network.Mark != 9 || !network.Mptcp || network.IPVersion != "4" {
		t.Fatalf("normalized magic network = %+v", network)
	}
}

func TestNaiveTransportNetworkDoesNotInheritDestinationFamily(t *testing.T) {
	udp4, err := normalizeNaiveNetwork("udp4")
	if err != nil {
		t.Fatal(err)
	}
	udp6, err := normalizeNaiveNetwork("udp6")
	if err != nil {
		t.Fatal(err)
	}
	udp4.Mark = 9
	udp4.Mptcp = true
	udp6.Mark = 9
	udp6.Mptcp = true

	transport4 := naiveTransportNetwork(udp4)
	transport6 := naiveTransportNetwork(udp6)
	if transport4.Network != "tcp" || transport4.IPVersion != "" || transport4.Mark != 9 || !transport4.Mptcp {
		t.Fatalf("IPv4 target transport = %+v", transport4)
	}
	if transport4.Encode() != transport6.Encode() {
		t.Fatalf("target families created different transports: %q != %q", transport4.Encode(), transport6.Encode())
	}
}

type naiveTransportTestDialer struct {
	network string
	address string
}

func (d *naiveTransportTestDialer) DialContext(_ context.Context, network, address string) (netproxy.Conn, error) {
	d.network = network
	d.address = address
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func TestNaiveIPv4TargetCanUseIPv6ProxyTransport(t *testing.T) {
	targetNetwork, err := normalizeNaiveNetwork("udp4")
	if err != nil {
		t.Fatal(err)
	}
	base := &naiveTransportTestDialer{}
	next := &cronetNextDialer{
		Dialer:  base,
		network: naiveTransportNetwork(targetNetwork),
	}
	conn, err := next.DialContext(context.Background(), "tcp", M.ParseSocksaddr("[2001:db8::10]:443"))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	physicalNetwork, err := netproxy.ParseMagicNetwork(base.network)
	if err != nil {
		t.Fatal(err)
	}
	if physicalNetwork.Network != "tcp" || physicalNetwork.IPVersion != "" {
		t.Fatalf("physical network = %+v, want family-independent tcp", physicalNetwork)
	}
	if base.address != "[2001:db8::10]:443" {
		t.Fatalf("proxy address = %q", base.address)
	}
}

func TestNaiveChainResolvesEveryHopWithoutTargetFamily(t *testing.T) {
	base := &naiveTestDialer{}
	inner := &cronetNaiveDialer{nextDialer: base}
	outer := &cronetNaiveDialer{nextDialer: inner}
	network := netproxy.MagicNetwork{Network: "tcp", Mark: 7, Mptcp: true, IPVersion: "4"}.Encode()

	addresses, err := outer.LookupIPAddr(context.Background(), network, "outer.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || base.lookupHost != "outer.example" {
		t.Fatalf("outer lookup = %v, host %q", addresses, base.lookupHost)
	}
	resolvedNetwork, err := netproxy.ParseMagicNetwork(base.lookupNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedNetwork.Network != "tcp" || resolvedNetwork.IPVersion != "" || resolvedNetwork.Mark != 7 || !resolvedNetwork.Mptcp {
		t.Fatalf("outer lookup network = %+v", resolvedNetwork)
	}

	if _, err = inner.LookupIPAddr(context.Background(), network, "inner.example"); err != nil {
		t.Fatal(err)
	}
	if base.lookupHost != "inner.example" {
		t.Fatalf("inner lookup host = %q", base.lookupHost)
	}
}

func TestCronetDNSResolverUsesWrappedDialer(t *testing.T) {
	baseDialer := &naiveTestDialer{}
	dialer := &cronetNextDialer{
		Dialer: baseDialer,
		network: netproxy.MagicNetwork{
			Network:   "tcp",
			Mark:      7,
			Mptcp:     true,
			IPVersion: "4",
		},
	}
	request := new(mDNS.Msg)
	request.SetQuestion("proxy.example.", mDNS.TypeA)
	response := newCronetDNSResolver(dialer)(context.Background(), request)
	if response.Rcode != mDNS.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("unexpected DNS response: %+v", response)
	}
	answer, ok := response.Answer[0].(*mDNS.A)
	if !ok || !answer.A.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("unexpected DNS answer: %v", response.Answer)
	}
	if baseDialer.lookupHost != "proxy.example" {
		t.Fatalf("lookup host = %q", baseDialer.lookupHost)
	}
	lookupNetwork, err := netproxy.ParseMagicNetwork(baseDialer.lookupNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if lookupNetwork.Network != "tcp" || lookupNetwork.Mark != 7 || !lookupNetwork.Mptcp || lookupNetwork.IPVersion != "" {
		t.Fatalf("lookup network = %+v", lookupNetwork)
	}
}

func TestNaiveResolverSurvivesHTTPHopAndStickyWrapper(t *testing.T) {
	for _, link := range []string{
		"naive://user:pass@outer.invalid",
		"naive://user:pass@outer.invalid -> http://127.0.0.1:8080",
	} {
		t.Run(link, func(t *testing.T) {
			base := &naiveTestDialer{}
			sticky := stickyip.NewStickyIpDialer(base, "outer.invalid:443", nil)
			d, _, err := newOwnedNetproxyDialerFromLink(preserveNodeResolver(sticky, base), nil, link)
			if err != nil {
				t.Fatal(err)
			}
			owned := d.(*ownedChainDialer)
			defer owned.Close()
			addresses, err := owned.LookupIPAddr(context.Background(), "tcp4", "outer.invalid")
			if err != nil || len(addresses) != 2 || base.lookupHost != "outer.invalid" {
				t.Fatalf("node resolver lost: addresses=%v err=%v host=%q", addresses, err, base.lookupHost)
			}
		})
	}
}

func TestOwnedDoubleNaiveChainClosesBothCronetResources(t *testing.T) {
	dialer, property, err := newOwnedNetproxyDialerFromLink(
		&naiveTestDialer{},
		nil,
		"naive://user:pass@outer.example#outer -> naive://user:pass@inner.example#inner",
	)
	if err != nil {
		t.Fatal(err)
	}
	owned, ok := dialer.(*ownedChainDialer)
	if !ok {
		t.Fatalf("dialer type = %T", dialer)
	}
	if len(owned.resources) != 2 {
		t.Fatalf("owned resources = %d, want 2", len(owned.resources))
	}
	if property.Address != "outer.example:443->inner.example:443" {
		t.Fatalf("chain address = %q", property.Address)
	}
	inner, ok := owned.resources[0].(*cronetNaiveDialer)
	if !ok {
		t.Fatalf("inner resource type = %T", owned.resources[0])
	}
	outer, ok := owned.resources[1].(*cronetNaiveDialer)
	if !ok {
		t.Fatalf("outer resource type = %T", owned.resources[1])
	}
	if outer.nextDialer != inner {
		t.Fatalf("outer next dialer = %T, want inner Naive", outer.nextDialer)
	}
	if err = owned.Close(); err != nil {
		t.Fatal(err)
	}
	if err = owned.Close(); err != nil {
		t.Fatal(err)
	}
	inner.access.Lock()
	innerClosed := inner.closed
	inner.access.Unlock()
	outer.access.Lock()
	outerClosed := outer.closed
	outer.access.Unlock()
	if !innerClosed || !outerClosed {
		t.Fatalf("closed state: inner=%v outer=%v", innerClosed, outerClosed)
	}
}

type uotTestStreamDialer struct {
	conn        net.Conn
	destination M.Socksaddr
}

func (d *uotTestStreamDialer) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	d.destination = destination
	return d.conn, nil
}

func (d *uotTestStreamDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet listen")
}

func TestUOTNetproxyConnRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	streamDialer := &uotTestStreamDialer{conn: clientConn}
	target := M.ParseSocksaddr("198.51.100.1:53")
	packetConn, err := (&uot.Client{Dialer: streamDialer, Version: uot.Version}).ListenPacket(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	conn := &uotNetproxyConn{Conn: packetConn.(net.Conn), PacketConn: packetConn}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	serverErr := make(chan error, 1)
	go func() {
		request, err := uot.ReadRequest(serverConn)
		if err != nil {
			serverErr <- err
			return
		}
		if request.IsConnect || request.Destination != target {
			serverErr <- fmt.Errorf("unexpected UoT request: %+v", request)
			return
		}
		destination, err := uot.AddrParser.ReadAddrPort(serverConn)
		if err != nil {
			serverErr <- err
			return
		}
		if destination.String() != "203.0.113.1:5353" {
			serverErr <- fmt.Errorf("unexpected packet destination %v", destination)
			return
		}
		var length uint16
		if err = binary.Read(serverConn, binary.BigEndian, &length); err != nil {
			serverErr <- err
			return
		}
		payload := make([]byte, length)
		if _, err = io.ReadFull(serverConn, payload); err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "query" {
			serverErr <- fmt.Errorf("unexpected payload %q", payload)
			return
		}
		if err = uot.AddrParser.WriteAddrPort(serverConn, destination); err == nil {
			err = binary.Write(serverConn, binary.BigEndian, uint16(len("response")))
		}
		if err == nil {
			_, err = serverConn.Write([]byte("response"))
		}
		serverErr <- err
	}()

	if streamDialer.destination.Fqdn != uot.MagicAddress {
		t.Fatalf("UoT stream destination = %v", streamDialer.destination)
	}
	if n, writeErr := conn.WriteTo([]byte("query"), "203.0.113.1:5353"); writeErr != nil || n != len("query") {
		t.Fatalf("WriteTo = %d, %v; want 5 payload bytes", n, writeErr)
	}
	buffer := make([]byte, 64)
	n, address, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "response" || address != netip.MustParseAddrPort("203.0.113.1:5353") {
		t.Fatalf("unexpected response %q from %v", buffer[:n], address)
	}
	if err = <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestUOTWriteReturnsPayloadLength(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	packetConn := uot.NewConn(client, uot.Request{Destination: M.ParseSocksaddr("192.0.2.1:53")})
	conn := &uotNetproxyConn{Conn: packetConn, PacketConn: packetConn}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, server) }()
	if n, err := conn.Write([]byte("query")); err != nil || n != len("query") {
		t.Fatalf("Write = %d, %v; want 5 payload bytes", n, err)
	}
	if n, err := conn.WriteTo([]byte("query"), "192.0.2.2:53"); err != nil || n != len("query") {
		t.Fatalf("WriteTo = %d, %v; want 5 payload bytes", n, err)
	}
}
