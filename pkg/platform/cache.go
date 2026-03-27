package platform

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ConfigCache struct {
	Dir string
	TTL time.Duration
}

type CacheEntry struct {
	Body     string    `json:"body"`
	ETag     string    `json:"etag"`
	StoredAt time.Time `json:"stored_at"`
}

func NewConfigCache(dir string) *ConfigCache {
	_ = os.MkdirAll(dir, 0o700)
	return &ConfigCache{Dir: dir, TTL: 60 * time.Second}
}

// DefaultCacheDir returns ~/.cache/bouncerfox.
func DefaultCacheDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "bouncerfox")
}

func (c *ConfigCache) path(key string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	return filepath.Join(c.Dir, "config-"+hash+".json")
}

func (c *ConfigCache) Store(key, body, etag string) {
	entry := CacheEntry{Body: body, ETag: etag, StoredAt: time.Now()}
	data, _ := json.Marshal(entry)
	_ = os.WriteFile(c.path(key), data, 0o600)
}

func (c *ConfigCache) Load(key string) (CacheEntry, bool) {
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return CacheEntry{}, false
	}
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return CacheEntry{}, false
	}
	if time.Since(entry.StoredAt) > c.TTL {
		return CacheEntry{}, false
	}
	return entry, true
}

func (c *ConfigCache) Invalidate(key string) {
	_ = os.Remove(c.path(key))
}

func (c *ConfigCache) InvalidateAll() {
	entries, _ := filepath.Glob(filepath.Join(c.Dir, "config-*.json"))
	for _, e := range entries {
		_ = os.Remove(e)
	}
}
