//go:build !linux || !cgo
// +build !linux !cgo

package inhouse

import (
	"context"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func Sign(ctx context.Context, signerVerifier *signver.SignerVerifier, path string) error {
	panic("not implemented on this platform")
}

func Verify(ctx context.Context, rootCertRefs []string, path string) error {
	panic("not implemented on this platform")
}
