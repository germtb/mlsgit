package storage

import (
	"bytes"
	"testing"
)

func TestFilterCachePutGet(t *testing.T) {
	paths := setupTestPaths(t)
	cache := NewFilterCache(paths)

	plaintext := []byte("hello world")
	ciphertext := "encrypted-data-here"

	if err := cache.Put("test.txt", plaintext, ciphertext); err != nil {
		t.Fatal(err)
	}

	gotPlain := cache.GetPlaintext("test.txt")
	if !bytes.Equal(gotPlain, plaintext) {
		t.Errorf("GetPlaintext = %q, want %q", gotPlain, plaintext)
	}

	gotCT, ok := cache.GetCiphertext("test.txt")
	if !ok {
		t.Fatal("GetCiphertext returned false")
	}
	if gotCT != ciphertext {
		t.Errorf("GetCiphertext = %q, want %q", gotCT, ciphertext)
	}
}

func TestFilterCacheMiss(t *testing.T) {
	paths := setupTestPaths(t)
	cache := NewFilterCache(paths)

	gotPlain := cache.GetPlaintext("nonexistent.txt")
	if gotPlain != nil {
		t.Errorf("expected nil for missing plaintext, got %v", gotPlain)
	}

	_, ok := cache.GetCiphertext("nonexistent.txt")
	if ok {
		t.Error("expected false for missing ciphertext")
	}
}

func TestFilterCacheInvalidateAll(t *testing.T) {
	paths := setupTestPaths(t)
	cache := NewFilterCache(paths)

	cache.Put("test.txt", []byte("data"), "ct")

	if err := cache.InvalidateAll(); err != nil {
		t.Fatal(err)
	}

	gotPlain := cache.GetPlaintext("test.txt")
	if gotPlain != nil {
		t.Error("expected nil after invalidation")
	}
}

func TestFilterCacheNestedPaths(t *testing.T) {
	paths := setupTestPaths(t)
	cache := NewFilterCache(paths)

	if err := cache.Put("dir/subdir/file.txt", []byte("nested"), "ct"); err != nil {
		t.Fatal(err)
	}

	got := cache.GetPlaintext("dir/subdir/file.txt")
	if !bytes.Equal(got, []byte("nested")) {
		t.Errorf("nested path = %q, want %q", got, "nested")
	}
}
