//go:build !linux
// +build !linux

package elf

import (
	"context"

	"github.com/sigstore/sigstore/pkg/signature"
)

func Sign(ctx context.Context, signerVerifier signature.SignerVerifier, path string) error {
	panic("not implemented on this platform")
}

func Verify(ctx context.Context, path string) error {
	panic("not implemented on this platform")
}
