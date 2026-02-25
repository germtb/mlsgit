package crypto

import (
	"bytes"
	"testing"
)

func TestB64EncodeURLSafe(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"hello", []byte("hello"), "aGVsbG8"},
		{"with special chars", []byte{0xfb, 0xff, 0xfe}, "-__-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := B64Encode(tt.data, true)
			if got != tt.want {
				t.Errorf("B64Encode(%v, true) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestB64EncodeStandard(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"hello", []byte("hello"), "aGVsbG8="},
		{"with special chars", []byte{0xfb, 0xff, 0xfe}, "+//+"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := B64Encode(tt.data, false)
			if got != tt.want {
				t.Errorf("B64Encode(%v, false) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestB64Roundtrip(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		urlSafe bool
	}{
		{"url-safe empty", []byte{}, true},
		{"url-safe bytes", []byte{0, 1, 2, 3, 255, 254, 253}, true},
		{"standard empty", []byte{}, false},
		{"standard bytes", []byte{0, 1, 2, 3, 255, 254, 253}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := B64Encode(tt.data, tt.urlSafe)
			decoded, err := B64Decode(encoded, tt.urlSafe)
			if err != nil {
				t.Fatalf("B64Decode error: %v", err)
			}
			if !bytes.Equal(decoded, tt.data) {
				t.Errorf("roundtrip mismatch: got %v, want %v", decoded, tt.data)
			}
		})
	}
}

func TestB64DecodeWithPadding(t *testing.T) {
	// URL-safe decode should handle both padded and unpadded input
	data := []byte("hello")
	encoded := B64Encode(data, true) // "aGVsbG8" (no padding)

	decoded, err := B64Decode(encoded, true)
	if err != nil {
		t.Fatalf("B64Decode without padding error: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("decoded = %v, want %v", decoded, data)
	}

	// Also with explicit padding
	decoded2, err := B64Decode(encoded+"=", true)
	if err != nil {
		t.Fatalf("B64Decode with padding error: %v", err)
	}
	if !bytes.Equal(decoded2, data) {
		t.Errorf("decoded with padding = %v, want %v", decoded2, data)
	}
}
