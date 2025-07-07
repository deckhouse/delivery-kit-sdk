package signature

import (
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	annoNameSignature = "io.deckhouse.delivery-kit.signature"
	annoNameCert      = "io.deckhouse.delivery-kit.cert"
	annoNameChain     = "io.deckhouse.delivery-kit.chain"
)

var (
	ErrNoSignatureAnnotation = errors.New("no signature annotation")
	ErrNoCertAnnotation      = errors.New("no cert annotation")
)

type Bundle struct {
	Signature BundleItem
	Cert      BundleItem
	Chain     BundleItem
}

func (b Bundle) ToMap() map[string]string {
	return map[string]string{
		annoNameSignature: b.Signature.Base64String(),
		annoNameCert:      b.Cert.Base64String(),
		annoNameChain:     b.Chain.Base64String(),
	}
}

func NewBundleFromMap(annotations map[string]string) (Bundle, error) {
	var sig, cert, chain BundleItem
	var err error

	if sigBase64Encoded, ok := annotations[annoNameSignature]; !ok {
		return Bundle{}, ErrNoSignatureAnnotation
	} else {
		if sig, err = base64.StdEncoding.DecodeString(sigBase64Encoded); err != nil {
			return Bundle{}, fmt.Errorf("signatrue decoding: %w", err)
		}
	}

	if certBase64Encoded, ok := annotations[annoNameCert]; !ok {
		return Bundle{}, ErrNoCertAnnotation
	} else {
		if cert, err = base64.StdEncoding.DecodeString(certBase64Encoded); err != nil {
			return Bundle{}, fmt.Errorf("cert decoding: %w", err)
		}
	}

	if chainBase64Encoded, ok := annotations[annoNameChain]; ok {
		if chain, err = base64.StdEncoding.DecodeString(chainBase64Encoded); err != nil {
			return Bundle{}, fmt.Errorf("chain decoding: %w", err)
		}
	}

	return NewBundle(sig, cert, chain), nil
}

type BundleItem []byte

func (item BundleItem) Base64String() string {
	return base64.StdEncoding.EncodeToString(item)
}

func NewBundle(sig, cert, chain BundleItem) Bundle {
	return Bundle{
		Signature: sig,
		Cert:      cert,
		Chain:     chain,
	}
}

func NewEmptyBundle() Bundle {
	return Bundle{
		Signature: BundleItem{},
		Cert:      BundleItem{},
		Chain:     BundleItem{},
	}
}
