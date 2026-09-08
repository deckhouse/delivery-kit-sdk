//go:build unix

package inhouse

import (
	"fmt"
	"os"
	"syscall"
)

func preserveOwnership(dst *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read ELF ownership: unexpected stat type %T", info.Sys())
	}
	if err := dst.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("preserve ELF ownership: %w", err)
	}
	return nil
}
