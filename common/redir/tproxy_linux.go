package redir

import (
	"encoding/binary"
	"net/netip"
	"syscall"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

func TProxy(fd uintptr, isIPv6 bool, isUDP bool) error {
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err == nil {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	}
	if err == nil && isIPv6 {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	}
	if isUDP {
		if err == nil {
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
		}
		if err == nil && isIPv6 {
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		}
	}
	return err
}

func TProxyWriteBack() control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error {
			if M.ParseSocksaddr(address).Addr.Is6() {
				return syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			} else {
				return syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}
		})
	}
}

var (
	tproxyReplyBind4 = netip.AddrFrom4([4]byte{192, 0, 0, 8})
	tproxyReplyBind6 = netip.AddrFrom16([16]byte{0x01, 15: 1})
)

// TProxyReplyBind — адрес привязки сокета, отвечающего за destination. Сам
// destination для привязки не годится: если это адрес нашей машины, сокет
// выигрывает у слушающего на 0.0.0.0 и отбирает чужие запросы, которые никто
// не читает. Заглушки (RFC 7600, RFC 6666) назначением пакета не бывают.
func TProxyReplyBind(destination netip.Addr) netip.Addr {
	if destination.Unmap().Is4() {
		return tproxyReplyBind4
	}
	return tproxyReplyBind6
}

// TProxyReplySource — управляющее сообщение, отправляющее пакет с адреса source.
func TProxyReplySource(source netip.Addr) []byte {
	if source = source.Unmap(); source.Is4() {
		return unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: source.As4()})
	}
	return unix.PktInfo6(&unix.Inet6Pktinfo{Addr: source.As16()})
}

func GetOriginalDestinationFromOOB(oob []byte) (netip.AddrPort, error) {
	controlMessages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, message := range controlMessages {
		if message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_RECVORIGDSTADDR {
			return netip.AddrPortFrom(M.AddrFromIP(message.Data[4:8]), binary.BigEndian.Uint16(message.Data[2:4])), nil
		} else if message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			return netip.AddrPortFrom(M.AddrFromIP(message.Data[8:24]), binary.BigEndian.Uint16(message.Data[2:4])), nil
		}
	}
	return netip.AddrPort{}, E.New("not found")
}
