package fakeip_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func openCacheFile(t *testing.T, path string) *cachefile.CacheFile {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	cacheFile := cachefile.New(context.Background(), logger, option.CacheFileOptions{Path: path, StoreFakeIP: true})
	scope := adapter.NewScope(context.Background(), logger)
	require.NoError(t, cacheFile.Start(adapter.StartStateInitialize, scope))
	t.Cleanup(func() { scope.Close() })
	return cacheFile
}

func openStore(t *testing.T, path string) *fakeip.Store {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	cacheFile := openCacheFile(t, path)
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cacheFile)
	store, err := fakeip.NewStore(ctx, logger, netip.MustParsePrefix("198.18.0.0/24"), netip.Prefix{})
	require.NoError(t, err)
	require.NoError(t, store.Start())
	return store
}

// Пул обёрнут, процесс убит с несброшенным буфером: поднятая база не должна
// выдавать прежний домен за адресом, уже отданным новому.
func TestStoreCrashAfterWrap(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cache.db")
	store := openStore(t, path)
	latest := make(map[netip.Addr]string)
	var last []netip.Addr
	for i := range 400 {
		domain := fmt.Sprintf("d%d.example", i)
		address, err := store.Create(domain, false)
		require.NoError(t, err)
		latest[address] = domain
		last = append(last, address)
		found, loaded := store.Lookup(address)
		require.True(t, loaded, domain)
		require.Equal(t, domain, found)
		again, err := store.Create(domain, false)
		require.NoError(t, err)
		require.Equal(t, address, again)
	}
	// Записи впереди указателя стёрты при резервировании блока, последние живы.
	for _, address := range last[len(last)-20:] {
		_, loaded := store.Lookup(address)
		require.True(t, loaded, latest[address])
	}
	for address, domain := range latest {
		found, loaded := store.Lookup(address)
		if loaded {
			require.Equal(t, domain, found)
			again, err := store.Create(domain, false)
			require.NoError(t, err)
			require.Equal(t, address, again)
		}
	}

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	crashedPath := filepath.Join(directory, "crashed.db")
	require.NoError(t, os.WriteFile(crashedPath, content, 0o600))
	crashed := openStore(t, crashedPath)
	for address, domain := range latest {
		found, loaded := crashed.Lookup(address)
		if loaded {
			require.Equal(t, domain, found, address)
		}
	}
	address, err := crashed.Create("after-crash.example", false)
	require.NoError(t, err)
	require.NotContains(t, last[len(last)-20:], address)
}

func TestStoreRejectsTinyRange(t *testing.T) {
	logger := log.NewNOPFactory().Logger()
	_, err := fakeip.NewStore(context.Background(), logger, netip.MustParsePrefix("198.18.0.0/31"), netip.Prefix{})
	require.Error(t, err)
	_, err = fakeip.NewStore(context.Background(), logger, netip.Prefix{}, netip.MustParsePrefix("fc00::/127"))
	require.Error(t, err)
}

// Домен переехал на новый адрес: переиспользование старого адреса не должно
// стирать его действующую запись — ни в буфере, ни в базе, ни при резервировании.
func TestCacheFileKeepsMovedDomain(t *testing.T) {
	oldAddress := netip.MustParseAddr("198.18.0.2")
	newAddress := netip.MustParseAddr("198.18.0.9")
	requireMoved := func(t *testing.T, cacheFile *cachefile.CacheFile) {
		t.Helper()
		address, loaded := cacheFile.FakeIPLoadDomain("moved.example", false)
		require.True(t, loaded)
		require.Equal(t, newAddress, address)
	}
	for _, flush := range []bool{true, false} {
		cacheFile := openCacheFile(t, filepath.Join(t.TempDir(), "cache.db"))
		store := func(address netip.Addr, domain string) {
			if flush {
				require.NoError(t, cacheFile.FakeIPStore(address, domain))
			} else {
				cacheFile.FakeIPStoreAsync(address, domain, nil)
			}
		}
		store(oldAddress, "moved.example")
		store(newAddress, "moved.example")
		store(oldAddress, "other.example")
		requireMoved(t, cacheFile)
		cacheFile.Flush()
		requireMoved(t, cacheFile)
	}
	cacheFile := openCacheFile(t, filepath.Join(t.TempDir(), "cache.db"))
	require.NoError(t, cacheFile.FakeIPStore(oldAddress, "moved.example"))
	require.NoError(t, cacheFile.FakeIPStore(newAddress, "moved.example"))
	require.NoError(t, cacheFile.FakeIPReserve(&adapter.FakeIPMetadata{}, oldAddress.Prev(), oldAddress))
	_, loaded := cacheFile.FakeIPLoad(oldAddress)
	require.False(t, loaded)
	requireMoved(t, cacheFile)
}
