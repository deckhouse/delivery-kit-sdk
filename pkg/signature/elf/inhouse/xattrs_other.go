//go:build !linux

package inhouse

import (
	"context"
	"fmt"
	"os"
)

func preservePermissionsAndAttributes(_ context.Context, _, dst *os.File, mode os.FileMode) error {
	if err := dst.Chmod(mode); err != nil {
		return fmt.Errorf("preserve ELF permissions: %w", err)
	}
	return nil
}
