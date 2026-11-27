//go:build integration

package include

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDesyncDomainUDPWithTCPFinalMask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err = target.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dnsSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int64
	dnsServer := &mdns.Server{PacketConn: dnsSocket, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
		queries.Add(1)
		reply := new(mdns.Msg)
		reply.SetReply(request)
		for _, question := range request.Question {
			if question.Name == "udp.desync.test." && question.Qtype == mdns.TypeA {
				reply.Answer = append(reply.Answer, &mdns.A{Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)})
			}
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = dnsServer.ActivateAndServe() }()
	defer dnsServer.Shutdown()
	boxCtx := Context(ctx)
	var options option.Options
	config := fmt.Sprintf(`{
		"log":{"disabled":true},
		"dns":{"servers":[
			{"type":"udp","tag":"real-resolver","server":"127.0.0.1","server_port":%d},
			{"type":"hosts","tag":"wrong-resolver","predefined":{"udp.desync.test":"192.0.2.1"}}
		],"final":"wrong-resolver"},
		"outbounds":[{"type":"desync","tag":"dpi","mode":"none",
			"domain_resolver":{"server":"real-resolver","strategy":"ipv4_only"},
			"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"10-20"}}]}
		}]
	}`, dnsSocket.LocalAddr().(*net.UDPAddr).Port)
	if err = SJSON.UnmarshalContext(boxCtx, []byte(config), &options); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Options: options, Context: boxCtx})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	outbound, _ := instance.Outbound().Outbound("dpi")
	logical := M.Socksaddr{Fqdn: "udp.desync.test", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}
	conn, err := outbound.ListenPacket(ctx, logical)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("domain UDP survives TCP-only finalmask")
	if _, err = conn.WriteTo(payload, logical); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, source, err := target.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("UDP payload changed: %q", buffer[:n])
	}
	if _, err = target.WriteTo(buffer[:n], source); err != nil {
		t.Fatal(err)
	}
	n, remote, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], payload) || remote.String() != logical.String() {
		t.Fatalf("unexpected reply %q from %s", buffer[:n], remote)
	}
	if queries.Load() == 0 {
		t.Fatal("configured resolver was not queried")
	}
}
