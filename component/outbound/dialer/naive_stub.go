//go:build !with_purego || !linux || !amd64

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func newCronetNaive(_ *D.ExtraOption, _ netproxy.Dialer, link string) (netproxy.Dialer, *D.Property, error) {
	options, err := parseNaiveLink(link)
	if err != nil {
		return nil, nil, err
	}
	return nil, options.property(link), fmt.Errorf("cronet naive support requires a linux/amd64 build with the with_purego tag")
}
