package awg

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordingRouter запоминает, куда эндпоинт направил соединение.
type recordingRouter struct {
	adapter.Router
	metadata   adapter.InboundContext
	prematched bool
}

func (r *recordingRouter) RouteConnectionEx(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.metadata = metadata
}

func (r *recordingRouter) RoutePacketConnectionEx(_ context.Context, _ N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.metadata = metadata
}

func (r *recordingRouter) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	r.prematched = true
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

// Локален только сам адрес интерфейса: соседа по его подсети заворачивать на
// loopback роутера нельзя.
func TestLocalAddressIsExact(t *testing.T) {
	cases := []struct {
		name, destination, want string
		local                   bool
	}{
		{"own v4", "10.82.0.1", "127.0.0.1", true},
		{"own v6", "fd00:82::1", "::1", true},
		{"neighbour v4", "10.82.0.77", "10.82.0.77", false},
		{"neighbour v6", "fd00:82::77", "fd00:82::77", false},
		{"network v4", "10.82.0.0", "10.82.0.0", false},
		{"foreign", "192.0.2.5", "192.0.2.5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := &recordingRouter{}
			ep := &Endpoint{
				router: router,
				logger: log.NewNOPFactory().Logger(),
				address: []netip.Prefix{
					netip.MustParsePrefix("10.82.0.1/24"),
					netip.MustParsePrefix("fd00:82::1/64"),
				},
			}
			source := M.ParseSocksaddr("10.82.0.9:1000")
			destination := M.SocksaddrFrom(netip.MustParseAddr(tc.destination), 443)
			want := M.SocksaddrFrom(netip.MustParseAddr(tc.want), 443)
			check := func(kind string) {
				t.Helper()
				if router.metadata.Destination != want {
					t.Errorf("%s: destination %s, want %s", kind, router.metadata.Destination, want)
				}
				if rewritten := router.metadata.OriginDestination.IsValid(); rewritten != tc.local {
					t.Errorf("%s: origin destination set = %v, want %v", kind, rewritten, tc.local)
				}
			}
			ep.NewConnectionEx(context.Background(), nil, source, destination, nil)
			check("tcp")
			router.metadata = adapter.InboundContext{}
			ep.NewPacketConnectionEx(context.Background(), nil, source, destination, nil)
			check("udp")

			verdict := ep.JudgeFlow(uint8(header.TCPProtocolNumber), source.AddrPort(), destination.AddrPort(), nil)
			if router.prematched == tc.local {
				t.Errorf("judge: rules consulted = %v, want %v", router.prematched, !tc.local)
			}
			if tc.local && verdict.Action != tun.ActionAccept {
				t.Errorf("judge: own address verdict %v, want accept", verdict.Action)
			}
		})
	}
}
