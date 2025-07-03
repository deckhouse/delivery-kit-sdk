package signver

import (
	"context"
	"crypto"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"
)

func NewVerifierFromCert(_ context.Context, certRef string) (signature.Verifier, error) {
	_, cert, err := LoadCertFromRef(certRef)
	if err != nil {
		return nil, fmt.Errorf("load cert from ref: %w", err)
	}
	return signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
}
