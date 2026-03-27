package platform

import (
	"testing"
	"time"
)

func TestConfigCache_StoreAndLoad(t *testing.T) {
	dir := t.TempDir()
	cache := NewConfigCache(dir)

	cache.Store("key1", "profile: recommended\n", `"etag1"`)
	entry, ok := cache.Load("key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if entry.Body != "profile: recommended\n" {
		t.Errorf("unexpected body: %q", entry.Body)
	}
	if entry.ETag != `"etag1"` {
		t.Errorf("unexpected etag: %q", entry.ETag)
	}
}

func TestConfigCache_ExpiredEntry(t *testing.T) {
	dir := t.TempDir()
	cache := NewConfigCache(dir)
	cache.TTL = 1 * time.Millisecond

	cache.Store("key2", "old", `"old"`)
	time.Sleep(5 * time.Millisecond)

	_, ok := cache.Load("key2")
	if ok {
		t.Error("expected cache miss for expired entry")
	}
}

func TestConfigCache_Invalidate(t *testing.T) {
	dir := t.TempDir()
	cache := NewConfigCache(dir)

	cache.Store("key3", "data", `"e"`)
	cache.Invalidate("key3")

	_, ok := cache.Load("key3")
	if ok {
		t.Error("expected cache miss after invalidation")
	}
}

func TestConfigCache_InvalidateAll(t *testing.T) {
	dir := t.TempDir()
	cache := NewConfigCache(dir)

	cache.Store("a", "data-a", `"ea"`)
	cache.Store("b", "data-b", `"eb"`)
	cache.InvalidateAll()

	if _, ok := cache.Load("a"); ok {
		t.Error("expected miss after InvalidateAll")
	}
	if _, ok := cache.Load("b"); ok {
		t.Error("expected miss after InvalidateAll")
	}
}
