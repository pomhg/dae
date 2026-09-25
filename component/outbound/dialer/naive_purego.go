//go:build with_purego && linux && amd64

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	mDNS "github.com/miekg/dns"
	cronet "github.com/sagernet/cronet-go"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

type cronetNaiveDialer struct {
	nextDialer netproxy.Dialer
	options    naiveLinkOptions
	ctx        context.Context
	cancel     context.CancelFunc

	access  sync.Mutex
	clients map[string]*cronet.NaiveClient
	closed  bool
}

func newCronetNaive(option *D.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *D.Property, error) {
	options, err := parseNaiveLink(link)
	if err != nil {
		return nil, nil, err
	}
	if options.allowInsecure || option != nil && option.AllowInsecure {
		return nil, nil, fmt.Errorf("cronet naive does not support insecure TLS verification")
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &cronetNaiveDialer{
		nextDialer: nextDialer,
		options:    *options,
		ctx:        ctx,
		cancel:     cancel,
		clients:    make(map[string]*cronet.NaiveClient),
	}, options.property(link), nil
}

func (d *cronetNaiveDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	magicNetwork, err := normalizeNaiveNetwork(network)
	if err != nil {
		return nil, err
	}
	destination := M.ParseSocksaddr(address)
	if !destination.IsValid() || destination.Port == 0 {
		return nil, fmt.Errorf("invalid destination %q", address)
	}

	client, err := d.clientFor(magicNetwork)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		return client.DialEarly(ctx, destination)
	case "udp":
		if !d.options.uotEnabled {
			return nil, fmt.Errorf("UDP is disabled for this naive node; remove uot=false to enable UoT")
		}
		uotClient := &uot.Client{
			Dialer:  &cronetNaiveStreamDialer{client: client},
			Version: d.options.uotVersion,
		}
		packetConn, err := uotClient.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		streamConn, ok := packetConn.(net.Conn)
		if !ok {
			_ = packetConn.Close()
			return nil, fmt.Errorf("unexpected UoT connection type %T", packetConn)
		}
		return &uotNetproxyConn{Conn: streamConn, PacketConn: packetConn}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *cronetNaiveDialer) clientFor(magicNetwork *netproxy.MagicNetwork) (*cronet.NaiveClient, error) {
	clientNetwork := naiveTransportNetwork(magicNetwork)
	key := clientNetwork.Encode()

	d.access.Lock()
	defer d.access.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if client := d.clients[key]; client != nil {
		return client, nil
	}

	nextDialer := &cronetNextDialer{
		Dialer:  d.nextDialer,
		network: clientNetwork,
	}
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		Context:               d.ctx,
		Logger:                logger.NOP(),
		ServerAddress:         M.ParseSocksaddr(d.options.address()),
		ServerName:            d.options.serverName,
		Username:              d.options.username,
		Password:              d.options.password,
		InsecureConcurrency:   d.options.insecureConcurrency,
		ExtraHeaders:          d.options.extraHeaders,
		Dialer:                nextDialer,
		DNSResolver:           newCronetDNSResolver(nextDialer),
		QUIC:                  d.options.quic,
		QUICCongestionControl: parseQUICCongestionControl(d.options.quicCongestionControl),
	})
	if err != nil {
		if strings.Contains(err.Error(), "library not found") {
			return nil, fmt.Errorf("%w; place the matching libcronet.so next to the dae executable", err)
		}
		return nil, err
	}
	if err = client.Start(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("start cronet naive client: %w", err)
	}
	d.clients[key] = client
	return client, nil
}

// naiveTransportNetwork keeps socket policy such as SO_MARK and MPTCP, but it
// deliberately does not inherit the destination address family. An IPv4
// destination can be reached through an IPv6 Naive server (and vice versa),
// matching sing-box detour semantics.
func naiveTransportNetwork(network *netproxy.MagicNetwork) netproxy.MagicNetwork {
	transportNetwork := *network
	transportNetwork.Network = "tcp"
	transportNetwork.IPVersion = ""
	return transportNetwork
}

func (d *cronetNaiveDialer) Close() error {
	d.access.Lock()
	if d.closed {
		d.access.Unlock()
		return nil
	}
	d.closed = true
	d.cancel()
	clients := make([]*cronet.NaiveClient, 0, len(d.clients))
	for _, client := range d.clients {
		clients = append(clients, client)
	}
	d.clients = nil
	d.access.Unlock()

	var firstErr error
	for _, client := range clients {
		if err := client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (d *cronetNaiveDialer) chainOwnedResource() chainResource {
	return d
}

// LookupIPAddr lets an outer Naive hop retain the resolver attached to the
// chain root instead of falling back to net.DefaultResolver. Each hop resolves
// its own server name, without inheriting the business destination's IP family.
func (d *cronetNaiveDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		magicNetwork = &netproxy.MagicNetwork{Network: "tcp"}
	}
	transportNetwork := naiveTransportNetwork(magicNetwork)
	return (&cronetNextDialer{
		Dialer:  d.nextDialer,
		network: transportNetwork,
	}).LookupIPAddr(ctx, host)
}

func normalizeNaiveNetwork(network string) (*netproxy.MagicNetwork, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
	case "tcp4", "udp4":
		magicNetwork.Network = strings.TrimSuffix(magicNetwork.Network, "4")
		magicNetwork.IPVersion = "4"
	case "tcp6", "udp6":
		magicNetwork.Network = strings.TrimSuffix(magicNetwork.Network, "6")
		magicNetwork.IPVersion = "6"
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
	return magicNetwork, nil
}

func parseQUICCongestionControl(value string) cronet.QUICCongestionControl {
	switch value {
	case "bbr":
		return cronet.QUICCongestionControlBBR
	case "bbr2":
		return cronet.QUICCongestionControlBBRv2
	case "cubic":
		return cronet.QUICCongestionControlCubic
	case "reno":
		return cronet.QUICCongestionControlReno
	default:
		return cronet.QUICCongestionControlDefault
	}
}

type cronetNaiveStreamDialer struct {
	client *cronet.NaiveClient
}

func (d *cronetNaiveStreamDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d.client.DialEarly(ctx, destination)
}

func (d *cronetNaiveStreamDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

type cronetNextDialer struct {
	netproxy.Dialer
	network netproxy.MagicNetwork
}

func (d *cronetNextDialer) transportNetwork(network string) string {
	magicNetwork := d.network
	magicNetwork.Network = strings.TrimSuffix(strings.TrimSuffix(network, "4"), "6")
	magicNetwork.IPVersion = ""
	return magicNetwork.Encode()
}

func (d *cronetNextDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, d.transportNetwork(network), destination.String())
	if err != nil {
		return nil, err
	}
	if netConn, ok := conn.(net.Conn); ok {
		return netConn, nil
	}
	if strings.HasPrefix(network, "udp") {
		packetConn, ok := conn.(netproxy.PacketConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("UDP dialer returned non-packet connection %T", conn)
		}
		return netproxy.NewFakeNetPacketConn(packetConn, &net.UDPAddr{}, destination.UDPAddr()), nil
	}
	return &netproxy.FakeNetConn{Conn: conn, RAddr: destination.TCPAddr()}, nil
}

func (d *cronetNextDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := d.Dialer.DialContext(ctx, d.transportNetwork("udp"), destination.String())
	if err != nil {
		return nil, err
	}
	if packetConn, ok := conn.(net.PacketConn); ok {
		return packetConn, nil
	}
	packetConn, ok := conn.(netproxy.PacketConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("UDP dialer returned non-packet connection %T", conn)
	}
	return netproxy.NewFakeNetPacketConn(packetConn, &net.UDPAddr{}, destination.UDPAddr()), nil
}

func (d *cronetNextDialer) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if resolver, ok := d.Dialer.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	}); ok {
		return resolver.LookupIPAddr(ctx, d.transportNetwork("tcp"), host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func newCronetDNSResolver(dialer *cronetNextDialer) cronet.DNSResolverFunc {
	return func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
		response := new(mDNS.Msg)
		response.SetReply(request)
		if len(request.Question) == 0 {
			return response
		}

		question := request.Question[0]
		if question.Qtype != mDNS.TypeA && question.Qtype != mDNS.TypeAAAA {
			return response
		}
		host := strings.TrimSuffix(question.Name, ".")
		addresses, err := dialer.LookupIPAddr(ctx, host)
		if err != nil {
			response.Rcode = mDNS.RcodeServerFailure
			return response
		}
		for _, address := range addresses {
			ip, ok := netip.AddrFromSlice(address.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			header := mDNS.RR_Header{Name: question.Name, Class: mDNS.ClassINET, Ttl: 60}
			switch {
			case question.Qtype == mDNS.TypeA && ip.Is4():
				header.Rrtype = mDNS.TypeA
				response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: net.IP(ip.AsSlice())})
			case question.Qtype == mDNS.TypeAAAA && ip.Is6():
				header.Rrtype = mDNS.TypeAAAA
				response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: net.IP(ip.AsSlice())})
			}
		}
		return response
	}
}

type uotNetproxyConn struct {
	net.Conn
	net.PacketConn
}

func (c *uotNetproxyConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, address, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	destination := M.SocksaddrFromNet(address)
	if !destination.Addr.IsValid() {
		return n, netip.AddrPort{}, fmt.Errorf("UoT returned non-IP address %q", destination.String())
	}
	return n, destination.AddrPort(), nil
}

func (c *uotNetproxyConn) WriteTo(p []byte, address string) (int, error) {
	destination := M.ParseSocksaddr(address)
	if !destination.IsValid() || destination.Port == 0 {
		return 0, fmt.Errorf("invalid UDP destination %q", address)
	}
	n, err := c.PacketConn.WriteTo(p, destination)
	if err == nil {
		// sing's non-vectorised UoT writer counts the frame header as well.
		// netproxy callers expect the number of payload bytes written.
		n = len(p)
	}
	return n, err
}

func (c *uotNetproxyConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil {
		n = len(p)
	}
	return n, err
}

func (c *uotNetproxyConn) Close() error {
	return c.Conn.Close()
}

func (c *uotNetproxyConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(deadline)
}

func (c *uotNetproxyConn) SetReadDeadline(deadline time.Time) error {
	return c.Conn.SetReadDeadline(deadline)
}

func (c *uotNetproxyConn) SetWriteDeadline(deadline time.Time) error {
	return c.Conn.SetWriteDeadline(deadline)
}

var (
	_ netproxy.Dialer = (*cronetNaiveDialer)(nil)
	_ interface {
		DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
		ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error)
	} = (*cronetNaiveStreamDialer)(nil)
	_ netproxy.FullConn = (*uotNetproxyConn)(nil)
)
