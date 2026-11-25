package redirect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

// Ответный сокет требует IP_TRANSPARENT (CAP_NET_ADMIN). Полный прогон:
//
//	unshare -Urn sh -c 'ip link set lo up; ip -6 addr add fd00::1/128 dev lo; go test ./protocol/redirect/ -run TestReply -v'
func requireTransparent(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("нет CAP_NET_ADMIN")
	} else if err != nil {
		t.Fatal(err)
	}
}

func newReplyWriter(t *testing.T, client net.PacketConn, destination M.Socksaddr) *tproxyPacketWriter {
	t.Helper()
	writer := &tproxyPacketWriter{
		ctx: context.Background(),
		listener: listener.New(listener.Options{
			Context: context.Background(),
			Logger:  log.StdLogger(),
		}),
		source:      client.LocalAddr().(*net.UDPAddr).AddrPort(),
		destination: destination,
	}
	t.Cleanup(func() {
		if writer.conn != nil {
			writer.conn.Close()
		}
	})
	return writer
}

func listenClient(t *testing.T, address string) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readFrom(t *testing.T, conn net.PacketConn) (string, netip.AddrPort) {
	t.Helper()
	buffer := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal("ответа нет: ", err)
	}
	addr := from.(*net.UDPAddr).AddrPort()
	return string(buffer[:n]), netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

// listenWildcard — чужой резолвер на 0.0.0.0 (на роутере это ndnproxy).
func listenWildcard(t *testing.T, network, address string) uint16 {
	t.Helper()
	listenConfig := net.ListenConfig{Control: control.ReuseAddr()}
	conn, err := listenConfig.ListenPacket(context.Background(), network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 64)
		for {
			_, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			conn.WriteTo([]byte("WILDCARD"), from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

// #132 в awg-manager: ответный сокет, занявший адрес роутера, отбирал запросы
// остальных клиентов у резолвера на 0.0.0.0.
func TestReplyDoesNotStealPort(t *testing.T) {
	requireTransparent(t)
	for _, tc := range []struct{ name, network, wildcard, client, destination string }{
		{"v4", "udp4", "0.0.0.0:0", "127.0.0.1:0", "127.0.0.2"},
		{"v6", "udp6", "[::]:0", "[::1]:0", "fd00::1"},
		// Резолвер самого роутера: заглушка не должна задеть и его.
		{"v4 loopback", "udp4", "0.0.0.0:0", "127.0.0.1:0", "127.0.0.1"},
		{"v6 loopback", "udp6", "[::]:0", "[::1]:0", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if conn, err := net.ListenPacket("udp", net.JoinHostPort(tc.destination, "0")); err != nil {
				t.Skip("нет адреса ", tc.destination)
			} else {
				conn.Close()
			}
			port := listenWildcard(t, tc.network, tc.wildcard)
			destination := M.ParseSocksaddrHostPort(tc.destination, port)

			client := listenClient(t, tc.client)
			writer := newReplyWriter(t, client, destination)
			if err := writer.WritePacket(buf.As([]byte("REPLY")), destination); err != nil {
				t.Fatal(err)
			}
			if payload, from := readFrom(t, client); payload != "REPLY" || from != destination.AddrPort() {
				t.Fatalf("ответ %q с %s, ожидался REPLY с %s", payload, from, destination)
			}
			if writer.conn == nil {
				t.Fatal("сокет сессии закрыт: кэш потерян, проверка ниже холостая")
			}

			other := listenClient(t, tc.client)
			other.WriteTo([]byte("q"), net.UDPAddrFromAddrPort(destination.AddrPort()))
			if payload, _ := readFrom(t, other); payload != "WILDCARD" {
				t.Fatalf("чужой запрос получил %q", payload)
			}
		})
	}
}

func TestReplyTwoSessionsSamePort(t *testing.T) {
	requireTransparent(t)
	destination := M.ParseSocksaddrHostPort("127.0.0.2", 45353)
	for range 2 {
		client := listenClient(t, "127.0.0.1:0")
		writer := newReplyWriter(t, client, destination)
		for _, want := range []string{"first", "cached"} {
			if err := writer.WritePacket(buf.As([]byte(want)), destination); err != nil {
				t.Fatal(err)
			}
			if payload, from := readFrom(t, client); payload != want || from != destination.AddrPort() {
				t.Fatalf("ответ %q с %s", payload, from)
			}
		}
	}
}

// Ответ не с того адреса, куда шла сессия (full-cone): сокет не кэшируется,
// источник — фактический.
func TestReplyOtherDestination(t *testing.T) {
	requireTransparent(t)
	client := listenClient(t, "127.0.0.1:0")
	writer := newReplyWriter(t, client, M.ParseSocksaddrHostPort("127.0.0.2", 45353))
	other := M.ParseSocksaddrHostPort("127.0.0.3", 45354)
	if err := writer.WritePacket(buf.As([]byte("cone")), other); err != nil {
		t.Fatal(err)
	}
	if payload, from := readFrom(t, client); payload != "cone" || from != other.AddrPort() {
		t.Fatalf("ответ %q с %s, ожидался с %s", payload, from, other)
	}
	if writer.conn != nil {
		t.Fatal("закэширован сокет чужого назначения")
	}
}

func TestReplyV6Source(t *testing.T) {
	requireTransparent(t)
	client, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skip("нет IPv6")
	}
	t.Cleanup(func() { client.Close() })
	destination := M.ParseSocksaddrHostPort("fd00::1", 45353)
	writer := newReplyWriter(t, client, destination)
	if err := writer.WritePacket(buf.As([]byte("v6")), destination); err != nil {
		t.Fatal(err)
	}
	if payload, from := readFrom(t, client); payload != "v6" || from != destination.AddrPort() {
		t.Fatalf("ответ %q с %s, ожидался с %s", payload, from, destination)
	}
}

func TestReplyMappedV4Destination(t *testing.T) {
	requireTransparent(t)
	client := listenClient(t, "127.0.0.1:0")
	destination := M.Socksaddr{Addr: netip.MustParseAddr("::ffff:127.0.0.2"), Port: 45353}
	writer := newReplyWriter(t, client, destination)
	if err := writer.WritePacket(buf.As([]byte("mapped")), destination); err != nil {
		t.Fatal(err)
	}
	if payload, from := readFrom(t, client); payload != "mapped" || from != netip.MustParseAddrPort("127.0.0.2:45353") {
		t.Fatalf("ответ %q с %s", payload, from)
	}
}

func TestReplyNonIPDestination(t *testing.T) {
	requireTransparent(t)
	// Клиент v6: у v4 запись упала бы и без проверки — на несовпадении семейств.
	client := listenClient(t, "[::1]:0")
	destination := M.Socksaddr{Fqdn: "localhost", Port: 45353}
	writer := newReplyWriter(t, client, destination)
	if err := writer.WritePacket(buf.As([]byte("x")), destination); err == nil {
		t.Fatal("имя вместо адреса обязано давать ошибку")
	}
}

// Запись через сокет сессии — горячий путь: источник не собирается заново.
func TestReplyCachedNoAllocs(t *testing.T) {
	requireTransparent(t)
	destination := M.ParseSocksaddrHostPort("127.0.0.2", 45353)
	writer := newReplyWriter(t, listenClient(t, "127.0.0.1:0"), destination)
	const runs = 100
	buffers := make([]*buf.Buffer, runs+2)
	for i := range buffers {
		buffers[i] = buf.As([]byte("x"))
	}
	next := 0
	write := func() {
		if err := writer.WritePacket(buffers[next], destination); err != nil {
			t.Fatal(err)
		}
		next++
	}
	write()
	if allocs := testing.AllocsPerRun(runs, write); allocs != 0 {
		t.Fatalf("аллокаций на пакет: %v", allocs)
	}
}
