//go:build !linux
// +build !linux

package custom

import (
	"context"
)

func Sign(ctx context.Context, path string, signerVerifier *signver.SignerVerifier) error {
	panic("not implemented on this platform")
}

func Verify(ctx context.Context, path, rootCert string) error {
	panic("not implemented on this platform")
}
