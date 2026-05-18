package tun

import "github.com/sagernet/sing/common/udpnat2"

type UDPNATMode uint8

const (
	UDPNATModeEndpointIndependent UDPNATMode = iota
	UDPNATModeDestinationDependent
)

func (m UDPNATMode) toUDPServiceMode() udpnat.NATMode {
	switch m {
	case UDPNATModeDestinationDependent:
		return udpnat.NATModeDestinationDependent
	default:
		return udpnat.NATModeEndpointIndependent
	}
}
