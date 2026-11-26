package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

// Сервер молча теряет первый пакет, как NAT при гонке conntrack на свежем
// кортеже; ответ должен прийти на повтор, а не через тайм-аут запроса.
func TestUDPTransportRetransmitsLostQuery(t *testing.T) {
	t.Parallel()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 2048)
		for first := true; ; first = false {
			n, addr, readErr := server.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			if first {
				continue
			}
			var request mDNS.Msg
			if request.Unpack(buffer[:n]) != nil {
				continue
			}
			response := new(mDNS.Msg)
			response.SetReply(&request)
			raw, _ := response.Pack()
			server.WriteTo(raw, addr)
		}
	}()
	transportDialer, err := dialer.NewDefault(context.Background(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	transport := NewUDPRaw(log.NewNOPFactory().Logger(), boxDNS.NewTransportAdapter(C.DNSTypeUDP, "test", nil), transportDialer, M.SocksaddrFromNet(server.LocalAddr()))
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err = transport.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	defer scope.Close()

	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if _, err = transport.Exchange(ctx, message); err != nil {
		t.Fatal("lost query was not retransmitted: ", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatal("answer took ", elapsed)
	}
}
