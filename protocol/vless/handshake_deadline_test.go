package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
)

// Сервер принял соединение и молчит (net.Pipe: запись блокируется, пока её
// никто не читает). Рукопожатие обязано вернуться по отмене контекста, а не
// висеть вечно.
func TestHandshakeWithDeadline_ReturnsOnCancel(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instance := &encryption.ClientInstance{}
	if err = instance.Init([][]byte{key.PublicKey().Bytes()}, 0, 0, ""); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, hErr := handshakeWithDeadline(ctx, client, instance)
		done <- hErr
	}()
	select {
	case hErr := <-done:
		if hErr == nil {
			t.Fatal("рукопожатие с молчащим сервером вернулось без ошибки")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("рукопожатие не вернулось после отмены контекста")
	}
}
