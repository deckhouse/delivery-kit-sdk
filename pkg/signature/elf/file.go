package elf

import (
	"context"
	
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func Sign(_ context.Context, _ *signver.SignerVerifier, _ string) error {
	return nil
}

func Verify(_ context.Context, _ *signver.SignerVerifier, _ string) error {
	return nil
}
