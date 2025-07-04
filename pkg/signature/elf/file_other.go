//go:build !linux
// +build !linux

package elf

import (
	"context"
)

func Sign(ctx context.Context, path string, signerVerifier signature.SignerVerifier) error {
	panic("not implemented on this platform")
}

func Verify(ctx context.Context, path string, certChain []*x509.Certificate) error {
	panic("not implemented on this platform")
}
