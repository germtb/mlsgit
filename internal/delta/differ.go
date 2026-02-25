// Package delta implements the diff-then-encrypt-then-sign pipeline.
package delta

import (
	"fmt"

	dmp "github.com/sergi/go-diff/diffmatchpatch"
)

var patcher = dmp.New()

// ComputeDelta computes a compact character-level delta from oldText to newText.
// Returns a string representation that can be applied with ApplyDelta.
func ComputeDelta(oldText, newText string) string {
	patches := patcher.PatchMake(oldText, newText)
	return patcher.PatchToText(patches)
}

// ApplyDelta applies a delta (produced by ComputeDelta) to oldText.
// Returns the patched text or an error if any hunk fails.
func ApplyDelta(oldText, delta string) (string, error) {
	patches, err := patcher.PatchFromText(delta)
	if err != nil {
		return "", fmt.Errorf("parse delta: %w", err)
	}
	newText, results := patcher.PatchApply(patches, oldText)
	for i, ok := range results {
		if !ok {
			return "", fmt.Errorf("delta patch failed at hunk %d", i)
		}
	}
	return newText, nil
}
