//go:build with_utls

package tls

import (
	"net"
	"slices"
	"testing"

	utls "github.com/metacubex/utls"
)

func clientHelloGroups(t *testing.T, id utls.ClientHelloID) (curves, shares []utls.CurveID) {
	t.Helper()
	client, server := net.Pipe()
	server.Close()
	defer client.Close()
	uConn, err := newUConn(client, &utls.Config{ServerName: "example.com"}, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	for _, ext := range uConn.Extensions {
		switch extension := ext.(type) {
		case *utls.SupportedCurvesExtension:
			curves = extension.Curves
		case *utls.KeyShareExtension:
			for _, share := range extension.KeyShares {
				shares = append(shares, share.Group)
			}
		}
	}
	return
}

func requireMLKEMFirst(t *testing.T, name string, shares []utls.CurveID) {
	t.Helper()
	mlkem := slices.Index(shares, utls.X25519MLKEM768)
	x25519 := slices.Index(shares, utls.X25519)
	if mlkem < 0 || x25519 < 0 || mlkem > x25519 {
		t.Errorf("%s: key shares %v, want X25519MLKEM768 before X25519", name, shares)
	}
}

// firefox и safari обязаны слать X25519MLKEM768 перед X25519 — иначе сервер
// REALITY Xray v26.9.8+ ClientHello отвергает.
func TestCustomFingerprintsSendMLKEM(t *testing.T) {
	for _, name := range []string{"firefox", "safari", "chrome"} {
		id, err := uTLSClientHelloID(name)
		if err != nil {
			t.Fatal(err)
		}
		_, shares := clientHelloGroups(t, id)
		requireMLKEMFirst(t, name, shares)
	}
}

// random выбирает отпечаток раз на процесс — проверяется каждый возможный.
func TestRandomFingerprintsSendMLKEM(t *testing.T) {
	if !slices.Contains(modernFingerprints, randomFingerprint) {
		t.Fatalf("random fingerprint %v is not in the list", randomFingerprint)
	}
	for _, id := range modernFingerprints {
		_, shares := clientHelloGroups(t, id)
		requireMLKEMFirst(t, id.Str(), shares)
	}
}

// randomized: шара без объявленной группы — нарушение TLS 1.3, группа MLKEM
// без шары — повод серверу REALITY отвергнуть ClientHello.
func TestRandomizedFingerprintPairsGroups(t *testing.T) {
	for range 100 {
		id := randomizedFingerprint
		seed, err := utls.NewPRNGSeed()
		if err != nil {
			t.Fatal(err)
		}
		id.Seed = seed
		curves, shares := clientHelloGroups(t, id)
		requireMLKEMFirst(t, "randomized", shares)
		for _, group := range shares {
			if !slices.Contains(curves, group) {
				t.Fatalf("key share %v is not in supported groups %v", group, curves)
			}
		}
	}
}
