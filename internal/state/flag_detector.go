package state

import (
	"regexp"
	"sync"
)

// DefaultFlagRegex matches typical AD flags like "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX1=".
const DefaultFlagRegex = `[A-Za-z0-9]{31}=`

// FlagDetector scans payloads for flag patterns.
type FlagDetector struct {
	mu sync.RWMutex
	re *regexp.Regexp
}

func NewFlagDetector(pattern string) (*FlagDetector, error) {
	if pattern == "" {
		pattern = DefaultFlagRegex
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &FlagDetector{re: re}, nil
}

// SetPattern swaps the regex at runtime.
func (d *FlagDetector) SetPattern(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.re = re
	return nil
}

// Scan returns true if a flag is present in the payload.
func (d *FlagDetector) Scan(payload []byte) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.re.Match(payload)
}

// Find returns all flag matches in the payload.
func (d *FlagDetector) Find(payload []byte) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.re.FindAllString(string(payload), -1)
}
