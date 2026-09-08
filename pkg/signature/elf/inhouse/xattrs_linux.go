package inhouse

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func preservePermissionsAndAttributes(ctx context.Context, src, dst *os.File, mode os.FileMode) error {
	attrs, err := readExtendedAttributes(ctx, src)
	if err != nil {
		return fmt.Errorf("read source attributes: %w", err)
	}
	for _, name := range []string{"security.ima", "security.evm"} {
		if _, ok := attrs[name]; ok {
			return fmt.Errorf("attribute %q requires integrity re-signing", name)
		}
	}
	if err := dst.Chmod(0o600); err != nil {
		return fmt.Errorf("make destination writable for attributes: %w", err)
	}
	inherited, err := readExtendedAttributes(ctx, dst)
	if err != nil {
		return fmt.Errorf("read destination attributes: %w", err)
	}
	for name := range inherited {
		if _, ok := attrs[name]; ok {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := unix.Fremovexattr(int(dst.Fd()), name); err != nil {
			return fmt.Errorf("remove inherited attribute %q: %w", name, err)
		}
	}
	names := slices.Sorted(maps.Keys(attrs))
	// An access ACL can revoke the write permission needed for user.* attributes.
	if i := slices.Index(names, "system.posix_acl_access"); i >= 0 {
		names = append(slices.Delete(names, i, i+1), "system.posix_acl_access")
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if old, ok := inherited[name]; ok && bytes.Equal(old, attrs[name]) {
			continue
		}
		if err := unix.Fsetxattr(int(dst.Fd()), name, attrs[name], 0); err != nil {
			return fmt.Errorf("write attribute %q: %w", name, err)
		}
	}
	if err := dst.Chmod(mode); err != nil {
		return fmt.Errorf("preserve ELF permissions: %w", err)
	}
	actual, err := readExtendedAttributes(ctx, dst)
	if err != nil {
		return fmt.Errorf("read written attributes: %w", err)
	}
	if !maps.EqualFunc(attrs, actual, bytes.Equal) {
		return fmt.Errorf("written attributes differ from source")
	}
	return nil
}

func readExtendedAttributes(ctx context.Context, file *os.File) (map[string][]byte, error) {
	// Linux limits both an xattr value and the returned name list to 64 KiB.
	buf := make([]byte, 64*1024)
	n, err := unix.Flistxattr(int(file.Fd()), buf)
	if errors.Is(err, unix.EOPNOTSUPP) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list attributes: %w", err)
	}
	attrs := make(map[string][]byte)
	if n == 0 {
		return attrs, nil
	}
	names := strings.Split(strings.TrimSuffix(string(buf[:n]), "\x00"), "\x00")
	total := n
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := unix.Fgetxattr(int(file.Fd()), name, buf)
		if err != nil {
			return nil, fmt.Errorf("read attribute %q: %w", name, err)
		}
		total += n
		if total > maxMetadataSize {
			return nil, fmt.Errorf("extended attributes exceed metadata budget")
		}
		attrs[name] = bytes.Clone(buf[:n])
	}
	return attrs, nil
}
