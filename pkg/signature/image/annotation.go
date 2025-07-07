package image

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/samber/lo"
)

const (
	annoNameSignature = "io.deckhouse.deliverykit.signature"
	annoNameCert      = "io.deckhouse.deliverykit.cert"
	annoNameChain     = "io.deckhouse.deliverykit.chain"
)

var (
	ErrNoSignatureAnnotation = errors.New("no signature annotation")
	ErrNoCertAnnotation      = errors.New("no cert annotation")
)

func bundleToAnnotations(bundle *signature.Bundle) map[string]string {
	return map[string]string{
		annoNameSignature: bundle.Signature.Base64String(),
		annoNameCert:      bundle.Cert.Base64String(),
		annoNameChain:     bundle.Chain.Base64String(),
	}
}

func newBundleFromAnnotations(annotations map[string]string) (*signature.Bundle, error) {
	var sig, cert, chain signature.BundleItem
	var err error

	if sigBase64Encoded, ok := annotations[annoNameSignature]; !ok {
		return nil, ErrNoSignatureAnnotation
	} else {
		if sig, err = base64.StdEncoding.DecodeString(sigBase64Encoded); err != nil {
			return nil, fmt.Errorf("signatrue decoding: %w", err)
		}
	}

	if certBase64Encoded, ok := annotations[annoNameCert]; !ok {
		return nil, ErrNoCertAnnotation
	} else {
		if cert, err = base64.StdEncoding.DecodeString(certBase64Encoded); err != nil {
			return nil, fmt.Errorf("cert decoding: %w", err)
		}
	}

	if chainBase64Encoded, ok := annotations[annoNameChain]; ok {
		if chain, err = base64.StdEncoding.DecodeString(chainBase64Encoded); err != nil {
			return nil, fmt.Errorf("chain decoding: %w", err)
		}
	}

	return signature.NewBundle(sig, cert, chain), nil
}

func safeAnnotations(annotations map[string]string) map[string]string {
	excludeList := []string{annoNameSignature, annoNameCert, annoNameChain}
	return lo.OmitByKeys(annotations, excludeList)
}
