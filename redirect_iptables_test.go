//go:build linux

package tun

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPTablesMarkProtocolsExcludeICMP(t *testing.T) {
	inet4 := &iptablesFamily{}
	inet6 := &iptablesFamily{isIPv6: true}
	inet6TProxy := &iptablesFamily{isIPv6: true, tproxy: true}

	require.Equal(t, []string{"udp", "icmp"}, iptablesMarkProtocols(inet4, false))
	require.Equal(t, []string{"udp", "icmpv6", "tcp"}, iptablesMarkProtocols(inet6, false))
	require.Equal(t, []string{"udp", "icmpv6"}, iptablesMarkProtocols(inet6TProxy, false))

	require.Equal(t, []string{"udp"}, iptablesMarkProtocols(inet4, true))
	require.Equal(t, []string{"udp", "tcp"}, iptablesMarkProtocols(inet6, true))
	require.Equal(t, []string{"udp"}, iptablesMarkProtocols(inet6TProxy, true))
}
