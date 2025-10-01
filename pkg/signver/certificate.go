package signver

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/blob"
)

func VerifyCert(pk crypto.PublicKey, certRef string) (*x509.Certificate, error) {
	cert, err := loadCertFromRef(certRef)
	if err != nil {
		return nil, fmt.Errorf("load cert from ref: %w", err)
	}
	if cryptoutils.EqualKeys(pk, cert.PublicKey) != nil {
		return nil, errors.New("public key in certificate does not match the provided public key")
	}
	return cert, nil
}

func loadCertFromRef(certRef string) (*x509.Certificate, error) {
	// Allow both DER and PEM encoding
	certBytes, err := blob.LoadBase64OrFile(certRef)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	// Handle PEM
	if bytes.HasPrefix(certBytes, []byte("-----")) {
		decoded, _ := pem.Decode(certBytes)
		if decoded.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certRef)
		}
		certBytes = decoded.Bytes
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse x509 certificate: %w", err)
	}
	return cert, nil
}

// ConcatChain takes intermediateRef... or rootRef and concatenates them into a chain.
func ConcatChain(intermediateOrRootRef ...string) ([]*x509.Certificate, string, error) {
	var builtChain []*x509.Certificate
	var builtPem []byte

	for _, ref := range intermediateOrRootRef {
		if ref == "" {
			continue
		}
		// Accept only PEM encoded certificate chain
		chainPem, err := blob.LoadBase64OrFile(ref)
		if err != nil {
			return nil, "", fmt.Errorf("reading certificate chain from reference: %w", err)
		}
		builtPem = append(builtPem, chainPem...)

		chainCerts, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(chainPem))
		if err != nil {
			return nil, "", fmt.Errorf("loading certificate chain: %w", err)
		}

		builtChain = append(builtChain, chainCerts...)
	}

	return builtChain, base64.StdEncoding.EncodeToString(builtPem), nil
}

// VerifyChain verifies certificate chain.
// chainRef must contain at least one certificate (root).
// If chainRef contains more than one certificate then the last one considered as root certificate.
func VerifyChain(certRef, chainRef string) ([]*x509.Certificate, []*x509.Certificate, error) {
	roots, intermediates, err := loadRootsAndIntermediatesFromRef(chainRef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading root and intermediate certificates: %w", err)
	}
	// Verify certificate chain is valid
	rootPool := x509.NewCertPool()
	rootPool.AddCert(roots[0])
	subPool := x509.NewCertPool()
	for _, c := range intermediates {
		subPool.AddCert(c)
	}
	leafCert, err := loadCertFromRef(certRef)
	if err != nil {
		return nil, nil, fmt.Errorf("loading leaf cert: %w", err)
	}
	if _, err = trustedCert(leafCert, rootPool, subPool); err != nil {
		return nil, nil, fmt.Errorf("validation of certificate chain: %w", err)
	}
	// Verify SCT if present in the leaf certificate.
	if contains, err := containsSCT(leafCert.Raw); err != nil {
		return nil, nil, err
	} else if contains {
		return nil, nil, errors.New("verification of embedded SCT is unsupported")
	}
	return roots, intermediates, nil
}

// loadRootsAndIntermediatesFromRef
// chainRef must contain at least one certificate (root certificate).
// If chainRef contains more than one certificate then the last one considered as root certificate.
func loadRootsAndIntermediatesFromRef(chainRef string) ([]*x509.Certificate, []*x509.Certificate, error) {
	if chainRef == "" {
		return nil, nil, fmt.Errorf("chainRef must not be empty")
	}

	// Accept only PEM encoded certificate chain
	certChainBytes, err := blob.LoadBase64OrFile(chainRef)
	if err != nil {
		return nil, nil, fmt.Errorf("reading certificate chain from reference: %w", err)
	}
	chainCerts, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certChainBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("loading certificate chain: %w", err)
	}

	if len(chainCerts) == 0 {
		return nil, nil, errors.New("no certificates in the chain")
	}

	return chainCerts[len(chainCerts)-1:], chainCerts[:len(chainCerts)-1], nil
}

// trustedCert
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/pkg/cosign/verify.go#L1436
// and modified after.
func trustedCert(cert *x509.Certificate, roots, intermediates *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime:   cert.NotBefore,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			// TODO: constraint with x509.ExtKeyUsageCodeSigning or not?
			x509.ExtKeyUsageAny,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("cert verification failed: %w", err)
	}
	return chains, nil
}

// ContainsSCT checks if the certificate contains embedded SCTs. cert can either be
// DER or PEM encoded.
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/pkg/cosign/verify_sct.go#L37
// as is.
func containsSCT(cert []byte) (bool, error) {
	embeddedSCTs, err := x509util.ParseSCTsFromCertificate(cert)
	if err != nil {
		return false, err
	}
	if len(embeddedSCTs) != 0 {
		return true, nil
	}
	return false, nil
}
