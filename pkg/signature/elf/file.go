package elf

import (
	"context"
	
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func Sign(_ context.Context, _ *signver.SignerVerifier, _ string) error {
	panic("not implemented yet")
}

func Verify(_ context.Context, _ *signver.SignerVerifier, _ string) error {
	panic("not implemented yet")
}
