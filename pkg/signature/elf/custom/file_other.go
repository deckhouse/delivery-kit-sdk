//go:build !linux
// +build !linux

package custom

import (
	"context"
	
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func Sign(ctx context.Context, signerVerifier *signver.SignerVerifier, path string) error {
	panic("not implemented on this platform")
}

func Verify(ctx context.Context, rootCert, path string) error {
	panic("not implemented on this platform")
}
