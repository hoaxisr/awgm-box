package sniff_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

// tlsClientHello снимает настоящий ClientHello с заданной группой обмена ключами.
func tlsClientHello(t testing.TB, curve tls.CurveID) []byte {
	t.Helper()
	return tlsClientHelloWith(t, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{curve},
	})
}

func tlsClientHelloWith(t testing.TB, config *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go tls.Client(client, config).Handshake()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	buffer := make([]byte, 4096)
	n, err := server.Read(buffer)
	require.NoError(t, err)
	return buffer[:n]
}

func TestSniffTLSClientHello(t *testing.T) {
	t.Parallel()
	for _, curve := range []tls.CurveID{tls.X25519, tls.X25519MLKEM768} {
		var metadata adapter.InboundContext
		err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(tlsClientHello(t, curve)))
		require.NoError(t, err)
		require.Equal(t, C.ProtocolTLS, metadata.Protocol)
		require.Equal(t, "example.com", metadata.Domain)
	}
}

func TestSniffTLSClientHelloTruncated(t *testing.T) {
	t.Parallel()
	hello := tlsClientHello(t, tls.X25519)
	var metadata adapter.InboundContext
	err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello[:len(hello)/2]))
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
}

// Сниффу нужен только SNI. Обмен ключами виден по аллокациям: на Go 1.26 разбор
// ClientHello даёт 39, а с ML-KEM и X25519 их 65.
const maxSniffTLSAllocs = 50

func TestSniffTLSClientHelloSkipsKeyExchange(t *testing.T) {
	hello := tlsClientHello(t, tls.X25519MLKEM768)
	allocs := testing.AllocsPerRun(20, func() {
		var metadata adapter.InboundContext
		_ = sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello))
	})
	t.Logf("allocs per ClientHello: %.0f", allocs)
	require.Less(t, allocs, float64(maxSniffTLSAllocs))
}

func BenchmarkSniffTLSClientHello(b *testing.B) {
	hello := tlsClientHello(b, tls.X25519MLKEM768)
	b.ReportAllocs()
	for b.Loop() {
		var metadata adapter.InboundContext
		_ = sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello))
	}
}

func echConfigList(t testing.TB, publicName string) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0xfe0d)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1)       // config_id
			b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x0001) // HKDF-SHA256
				b.AddUint16(0x0001) // AES-128-GCM
			})
			b.AddUint8(32) // maximum_name_length
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
			b.AddUint16(0) // extensions
		})
	})
	return b.BytesOrPanic()
}

// Внешнее имя ECH не перебивает домен, известный из DNS; обычный ClientHello
// к тому же имени — перебивает. Обмен ключами при этом не считается.
func TestSniffTLSClientHelloECHPublicName(t *testing.T) {
	t.Parallel()
	const publicName = "ech.example.net"
	echHello := tlsClientHelloWith(t, &tls.Config{
		ServerName:                     "inner.example.com",
		InsecureSkipVerify:             true,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: echConfigList(t, publicName),
	})
	plainHello := tlsClientHelloWith(t, &tls.Config{ServerName: publicName, InsecureSkipVerify: true})
	for _, testCase := range []struct {
		name          string
		hello         []byte
		echPublicName string
		domain        string
	}{
		{"ech, public name known", echHello, publicName, "mapped.example.com"},
		{"ech, public name unknown", echHello, "", publicName},
		{"ech, another public name", echHello, "other.example.net", publicName},
		{"plain hello to public name", plainHello, publicName, publicName},
	} {
		metadata := adapter.InboundContext{Domain: "mapped.example.com", ECHPublicName: testCase.echPublicName}
		err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(testCase.hello))
		require.NoError(t, err, testCase.name)
		require.Equal(t, C.ProtocolTLS, metadata.Protocol, testCase.name)
		require.Equal(t, testCase.domain, metadata.Domain, testCase.name)
	}
}
