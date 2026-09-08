//go:build !unix

package inhouse

import "os"

// Non-Unix platforms do not expose POSIX ownership through FileInfo.Sys.
func preserveOwnership(_ *os.File, _ os.FileInfo) error {
	return nil
}
