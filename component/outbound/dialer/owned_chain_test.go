/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type chainCloseTestDialer struct{}

func (*chainCloseTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("unexpected dial")
}

type countedChainResource struct {
	name  string
	order *[]string
	calls int
}

func (r *countedChainResource) Close() error {
	r.calls++
	*r.order = append(*r.order, r.name)
	return nil
}

func TestOwnedChainClosesOuterToInnerExactlyOnce(t *testing.T) {
	var order []string
	inner := &countedChainResource{name: "inner", order: &order}
	outer := &countedChainResource{name: "outer", order: &order}
	dialer := &ownedChainDialer{
		Dialer:     &chainCloseTestDialer{},
		resources:  []chainResource{inner, outer},
		topManaged: true,
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.calls != 1 || outer.calls != 1 {
		t.Fatalf("close calls: inner=%d outer=%d", inner.calls, outer.calls)
	}
	if len(order) != 2 || order[0] != "outer" || order[1] != "inner" {
		t.Fatalf("close order = %v", order)
	}
}

func TestControlPlaneAddressHostsFromChain(t *testing.T) {
	hosts := controlPlaneAddressHosts("Outer.Example:443->[2001:db8::1]:443->inner.example.:8443->outer.example:443")
	if !slices.Equal(hosts, []string{"Outer.Example", "inner.example.", "outer.example"}) {
		t.Fatalf("control hosts = %v", hosts)
	}
}
