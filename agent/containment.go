package main

import (
	"os"
)

// Initialize quarantine if it doesn't exist.
// This is a no-op if quarantine already exists.
func CreateQuarantine() error {
	//TODO:
}

func QuarantineFile(path string) error {
	return os.Rename(path, ResolveQuarantinePath(path))
}
