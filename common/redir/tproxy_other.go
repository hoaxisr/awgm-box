//go:build !linux

package redir

import (
	"net/netip"
	"os"

	"github.com/sagernet/sing/common/control"
)

func TProxy(fd uintptr, isIPv6 bool, isUDP bool) error {
	return os.ErrInvalid
}

func TProxyWriteBack() control.Func {
	return nil
}

func TProxyReplyBind(destination netip.Addr) netip.Addr {
	return netip.Addr{}
}

func TProxyReplySource(source netip.Addr) []byte {
	return nil
}

func GetOriginalDestinationFromOOB(oob []byte) (netip.AddrPort, error) {
	return netip.AddrPort{}, os.ErrInvalid
}
