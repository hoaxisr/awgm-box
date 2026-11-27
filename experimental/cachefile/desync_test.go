package cachefile

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestDesyncCoalescedShutdownPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cache := openDesyncTestCacheFile(t, path)
	for i := range 20 {
		if err := cache.StoreDesync("partition", []byte(fmt.Sprintf(`{"version":1,"event":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := cache.view(func(tx *bbolt.Tx) error {
		bucket := cache.bucket(tx, bucketDesync)
		if bucket != nil && bucket.Get([]byte("partition")) != nil {
			t.Fatal("event wrote immediately to database")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	expected := []byte(`{"version":1,"event":19}`)
	got, err := cache.LoadDesync("partition")
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("pending load %s %v", got, err)
	}
	if err = cache.Close(); err != nil {
		t.Fatal(err)
	}
	cache = openDesyncTestCacheFile(t, path)
	defer cache.Close()
	got, err = cache.LoadDesync("partition")
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("shutdown did not persist: %s %v", got, err)
	}
	if err = cache.ClearDesync("partition"); err != nil {
		t.Fatal(err)
	}
	if err = cache.FlushDesync(); err != nil {
		t.Fatal(err)
	}
	got, err = cache.LoadDesync("partition")
	if err != nil || len(got) > 0 {
		t.Fatalf("clear failed %s %v", got, err)
	}
}
func TestDesyncConcurrentClearAndFlush(t *testing.T) {
	cache := openDesyncTestCacheFile(t, filepath.Join(t.TempDir(), "cache.db"))
	defer cache.Close()
	var group sync.WaitGroup
	for i := range 4 {
		group.Go(func() {
			for j := range 20 {
				key := fmt.Sprintf("p%d", i)
				if err := cache.StoreDesync(key, []byte(`{"version":1}`)); err != nil {
					t.Error(err)
				}
				if j%3 == 0 {
					if err := cache.FlushDesync(); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	group.Wait()
	if err := cache.ClearDesync(""); err != nil {
		t.Fatal(err)
	}
	if err := cache.FlushDesync(); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		data, err := cache.LoadDesync(fmt.Sprintf("p%d", i))
		if err != nil || len(data) > 0 {
			t.Fatalf("clear resurrected data: %s %v", data, err)
		}
	}
}

// desyncTestCacheFile is a cache file with the scope it was started with: closing the scope
// closes the file, as when sing-box stops.
type desyncTestCacheFile struct {
	*CacheFile
	scope *adapter.Scope
}

func (f *desyncTestCacheFile) Close() error {
	return f.scope.Close()
}

func openDesyncTestCacheFile(t *testing.T, path string) *desyncTestCacheFile {
	t.Helper()
	cacheFile := New(context.Background(), logger.NOP(), option.CacheFileOptions{Enabled: true, Path: path, StoreFakeIP: true})
	scope := adapter.NewScope(context.Background(), logger.NOP())
	if err := cacheFile.Start(adapter.StartStateInitialize, scope); err != nil {
		scope.Close()
		t.Fatal(err)
	}
	return &desyncTestCacheFile{cacheFile, scope}
}
