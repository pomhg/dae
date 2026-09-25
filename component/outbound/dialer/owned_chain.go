/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	obcommon "github.com/daeuniverse/outbound/common"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type chainResource interface {
	Close() error
}

type chainIPResolver interface {
	LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
}

// Preserve the node resolver across wrappers and protocol hops that expose
// only DialContext. Cronet resolves its server before dialing the next hop.
type resolverPreservingDialer struct {
	netproxy.Dialer
	chainIPResolver
}

func preserveNodeResolver(dialer, base netproxy.Dialer) netproxy.Dialer {
	if _, ok := dialer.(chainIPResolver); ok {
		return dialer
	}
	if resolver, ok := base.(chainIPResolver); ok {
		return &resolverPreservingDialer{Dialer: dialer, chainIPResolver: resolver}
	}
	return dialer
}

type chainOwnedResourceProvider interface {
	chainOwnedResource() chainResource
}

// ownedChainDialer owns protocol resources created at every hop. The outbound
// package nests dialers for I/O but only exposes the outermost closer, so an
// inner Cronet engine otherwise survives a reload.
type ownedChainDialer struct {
	netproxy.Dialer
	resources  []chainResource // construction order: inner to outer
	topManaged bool

	closeOnce sync.Once
	closeErr  error
}

func (d *ownedChainDialer) Close() error {
	d.closeOnce.Do(func() {
		var closeErrors []error
		if !d.topManaged {
			if closer, ok := d.Dialer.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					closeErrors = append(closeErrors, err)
				}
			}
		}
		for i := len(d.resources) - 1; i >= 0; i-- {
			if err := d.resources[i].Close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		d.closeErr = errors.Join(closeErrors...)
	})
	return d.closeErr
}

func (d *ownedChainDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	resolver, ok := d.Dialer.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	return resolver.LookupIPAddr(ctx, network, host)
}

// newOwnedNetproxyDialerFromLink mirrors outbound's chain construction while
// retaining every hop resource so the whole chain can be retired on reload.
func newOwnedNetproxyDialerFromLink(base netproxy.Dialer, option *D.ExtraOption, link string) (netproxy.Dialer, *D.Property, error) {
	overwrittenName, linklike := obcommon.GetTagFromLinkLikePlaintext(link)
	links := strings.Split(linklike, "->")
	property := &D.Property{Link: linklike}
	current := base
	resources := make([]chainResource, 0, len(links))
	topManaged := false

	for i := len(links) - 1; i >= 0; i-- {
		hopLink := strings.TrimSpace(links[i])
		if hopLink == "" {
			return nil, nil, fmt.Errorf("empty proxy hop in chain")
		}
		hopDialer, hopProperty, err := D.NewNetproxyDialerFromLink(preserveNodeResolver(current, base), option, hopLink)
		if err != nil {
			return nil, nil, err
		}
		current = hopDialer
		prependChainProperty(property, hopProperty)

		topManaged = false
		if provider, ok := hopDialer.(chainOwnedResourceProvider); ok {
			resource := provider.chainOwnedResource()
			if resource != nil {
				resources = append(resources, resource)
				topManaged = true
			}
		}
	}
	if overwrittenName != "" {
		property.Name = overwrittenName
	}
	if len(resources) == 0 {
		return current, property, nil
	}
	return &ownedChainDialer{
		Dialer:     current,
		resources:  resources,
		topManaged: topManaged,
	}, property, nil
}

func prependChainProperty(property, hop *D.Property) {
	if property.Name == "" {
		property.Name = hop.Name
	} else {
		property.Name = hop.Name + "->" + property.Name
	}
	if property.Protocol == "" {
		property.Protocol = hop.Protocol
	} else {
		property.Protocol = hop.Protocol + "->" + property.Protocol
	}
	if property.Address == "" {
		property.Address = hop.Address
	} else {
		property.Address = hop.Address + "->" + property.Address
	}
}

var _ netproxy.Dialer = (*ownedChainDialer)(nil)
