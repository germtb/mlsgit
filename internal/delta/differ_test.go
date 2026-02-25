package delta

import (
	"testing"
)

func TestComputeApplyDelta(t *testing.T) {
	tests := []struct {
		name    string
		old     string
		new     string
	}{
		{"simple edit", "hello world", "hello Go world"},
		{"append", "hello", "hello world"},
		{"prepend", "world", "hello world"},
		{"replace all", "foo", "bar"},
		{"empty to text", "", "new content"},
		{"text to empty", "old content", ""},
		{"identical", "same", "same"},
		{"multiline", "line1\nline2\n", "line1\nline2\nline3\n"},
		{"unicode", "hello", "hello \u4e16\u754c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delta := ComputeDelta(tt.old, tt.new)
			result, err := ApplyDelta(tt.old, delta)
			if err != nil {
				t.Fatalf("ApplyDelta error: %v", err)
			}
			if result != tt.new {
				t.Errorf("ApplyDelta = %q, want %q", result, tt.new)
			}
		})
	}
}

func TestApplyDeltaInvalid(t *testing.T) {
	_, err := ApplyDelta("hello", "not a valid delta@@")
	if err == nil {
		t.Fatal("expected error for invalid delta")
	}
}
