/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type controlHostsTestDialer struct{}

func (controlHostsTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("unexpected dial")
}

func TestRouterWrapNodeDialerRetainsAllChainControlHosts(t *testing.T) {
	wrapped, err := (&Router{}).WrapNodeDialer(controlHostsTestDialer{}, NodeMeta{
		Name:         "chain",
		AddressHosts: []string{"outer.example", "inner.example", "INNER.EXAMPLE.", " "},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolving, ok := wrapped.(*resolvingDialer)
	if !ok {
		t.Fatalf("wrapped dialer type = %T", wrapped)
	}
	if !slices.Equal(resolving.controlHosts, []string{"outer.example", "inner.example"}) {
		t.Fatalf("control hosts = %v", resolving.controlHosts)
	}
	if !containsDNSHost(resolving.controlHosts, "INNER.example.") {
		t.Fatal("inner chain hop is not recognized as a control host")
	}
}
