//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

var (
	realityTestTime    = time.Unix(1_000_000_000, 0)
	realityTestShortID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
)

func newRealityTestClient(t *testing.T, id utls.ClientHelloID, mlkem bool, config *utls.Config) (*RealityClientConfig, *ecdh.PrivateKey) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	config.ServerName = "example.com"
	return &RealityClientConfig{
		context.Background(),
		&UTLSClientConfig{ctx: context.Background(), config: config, id: id},
		privateKey.PublicKey().Bytes(),
		realityTestShortID,
		mlkem,
	}, privateKey
}

// captureRealityHello снимает ClientHello и расшифровывает SessionId так, как
// это делает сервер REALITY.
func captureRealityHello(t *testing.T, config *RealityClientConfig, privateKey *ecdh.PrivateKey) (sessionID []byte, groups []uint16) {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_, _ = config.ClientHandshake(context.Background(), client)
	}()
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	var recordHeader [5]byte
	_, err := io.ReadFull(server, recordHeader[:])
	require.NoError(t, err)
	hello := make([]byte, binary.BigEndian.Uint16(recordHeader[3:]))
	_, err = io.ReadFull(server, hello)
	require.NoError(t, err)

	var (
		message                                        = cryptobyte.String(hello[4:])
		version                                        uint16
		random                                         []byte
		encrypted, suites, compressions, extensionData cryptobyte.String
		ecdheKey                                       []byte
	)
	require.True(t, message.ReadUint16(&version) && message.ReadBytes(&random, 32) &&
		message.ReadUint8LengthPrefixed(&encrypted) && message.ReadUint16LengthPrefixed(&suites) &&
		message.ReadUint8LengthPrefixed(&compressions) && message.ReadUint16LengthPrefixed(&extensionData))
	for !extensionData.Empty() {
		var extensionType uint16
		var extension cryptobyte.String
		require.True(t, extensionData.ReadUint16(&extensionType) && extensionData.ReadUint16LengthPrefixed(&extension))
		if extensionType != 51 { // key_share
			continue
		}
		var shares cryptobyte.String
		require.True(t, extension.ReadUint16LengthPrefixed(&shares))
		for !shares.Empty() {
			var group uint16
			var key cryptobyte.String
			require.True(t, shares.ReadUint16(&group) && shares.ReadUint16LengthPrefixed(&key))
			groups = append(groups, group)
			if group == uint16(utls.X25519) {
				ecdheKey = key
			}
		}
	}
	require.NotEmpty(t, ecdheKey)
	publicKey, err := ecdh.X25519().NewPublicKey(ecdheKey)
	require.NoError(t, err)
	authKey, err := privateKey.ECDH(publicKey)
	require.NoError(t, err)
	_, err = io.ReadFull(hkdf.New(sha256.New, authKey, random[:20], []byte("REALITY")), authKey)
	require.NoError(t, err)
	block, err := aes.NewCipher(authKey)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	ciphertext := append([]byte(nil), encrypted...)
	clear(hello[39 : 39+32])
	sessionID, err = aead.Open(nil, random[20:], ciphertext, hello)
	require.NoError(t, err)
	return
}

// Версия клиента, время из конфигурации и short_id доходят до сервера; шару
// X25519MLKEM768 решает support_x25519mlkem768.
func TestRealityClientSessionID(t *testing.T) {
	t.Parallel()
	for _, id := range modernFingerprints {
		for _, mlkem := range []bool{true, false} {
			config, privateKey := newRealityTestClient(t, id, mlkem, &utls.Config{
				Time: func() time.Time { return realityTestTime },
			})
			sessionID, groups := captureRealityHello(t, config, privateKey)
			require.Equal(t, []byte{26, 10, 31, 0}, sessionID[:4], id.Str())
			require.Equal(t, uint32(realityTestTime.Unix()), binary.BigEndian.Uint32(sessionID[4:8]), id.Str())
			require.Equal(t, realityTestShortID[:], sessionID[8:16], id.Str())
			if mlkem {
				require.Contains(t, groups, uint16(utls.X25519MLKEM768), id.Str())
			} else {
				require.NotContains(t, groups, uint16(utls.X25519MLKEM768), id.Str())
			}
		}
	}
}

// Без времени в конфигурации идёт системное.
func TestRealityClientSessionIDSystemTime(t *testing.T) {
	t.Parallel()
	config, privateKey := newRealityTestClient(t, utls.HelloChrome_Auto, true, &utls.Config{})
	sessionID, _ := captureRealityHello(t, config, privateKey)
	stamp := time.Unix(int64(binary.BigEndian.Uint32(sessionID[4:8])), 0)
	require.WithinDuration(t, time.Now(), stamp, time.Minute)
}

// Не-REALITY сертификат проверяется корнями и временем из конфигурации:
// годный доводит до «не прошла проверка REALITY», негодный рвёт handshake.
func TestRealityClientVerifiesWithConfig(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              []string{"example.com"},
		NotBefore:             realityTestTime.Add(-time.Hour),
		NotAfter:              realityTestTime.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	trusted := x509.NewCertPool()
	trusted.AddCert(certificate)

	handshake := func(config *utls.Config) error {
		realityConfig, _ := newRealityTestClient(t, utls.HelloChrome_Auto, true, config)
		// Не net.Pipe: встречные записи alert и полёта сервера встали бы намертво.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		client, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer client.Close()
		require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
		server, err := listener.Accept()
		require.NoError(t, err)
		go func() {
			defer server.Close()
			_ = tls.Server(server, &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			}).Handshake()
		}()
		_, err = realityConfig.ClientHandshake(context.Background(), client)
		return err
	}
	past := func() time.Time { return realityTestTime }
	require.ErrorContains(t, handshake(&utls.Config{Time: past, RootCAs: trusted}), "reality verification failed")
	var authorityError x509.UnknownAuthorityError
	require.ErrorAs(t, handshake(&utls.Config{Time: past, RootCAs: x509.NewCertPool()}), &authorityError)
	var invalidError x509.CertificateInvalidError
	require.ErrorAs(t, handshake(&utls.Config{RootCAs: trusted}), &invalidError)
	require.Equal(t, x509.Expired, invalidError.Reason)
}
