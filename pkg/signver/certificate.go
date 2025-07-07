package signver

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/blob"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func VerifyCert(pk crypto.PublicKey, certRef string) (*x509.Certificate, error) {
	cert, err := LoadCertFromRef(certRef)
	if err != nil {
		return nil, fmt.Errorf("load cert from ref: %w", err)
	}
	if cryptoutils.EqualKeys(pk, cert.PublicKey) != nil {
		return nil, errors.New("public key in certificate does not match the provided public key")
	}
	return cert, nil
}

func LoadCertFromRef(certRef string) (*x509.Certificate, error) {
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

// VerifyChain verifies certificate chain.
// rootRef argument could be empty string, file path or base64 encoded string.
// if rootRef is empty string, verification assumes that rootCert is last certificate in the chain.
// if rootRef is noy empty string (file path or base64 string), verification uses that certificate as rootCert.
func VerifyChain(certRef, chainRef, rootRef string) ([]*x509.Certificate, []*x509.Certificate, error) {
	roots, intermediates, err := LoadRootsAndIntermediatesFromRef(chainRef, rootRef)
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
	leafCert, err := LoadCertFromRef(certRef)
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

func LoadRootsAndIntermediatesFromRef(chainRef, rootRef string) ([]*x509.Certificate, []*x509.Certificate, error) {
	var rootCerts []*x509.Certificate
	var intermediateCerts []*x509.Certificate

	if chainRef != "" {
		// Accept only PEM encoded certificate chain
		certChainBytes, err := blob.LoadBase64OrFile(chainRef)
		if err != nil {
			return nil, nil, fmt.Errorf("reading certificate chain from reference: %w", err)
		}
		intermediateCerts, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certChainBytes))
		if err != nil {
			return nil, nil, fmt.Errorf("loading certificate chain: %w", err)
		}
	}

	if rootRef != "" {
		// Accept only PEM encoded certificate chain
		rootCertBytes, err := blob.LoadBase64OrFile(rootRef)
		if err != nil {
			return nil, nil, fmt.Errorf("reading certificate chain from reference: %w", err)
		}
		rootCerts, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(rootCertBytes))
		if err != nil {
			return nil, nil, fmt.Errorf("loading certificate chain: %w", err)
		}
	}

	if len(rootCerts) == 0 && len(intermediateCerts) == 0 {
		return nil, nil, errors.New("root certificate must be present in certificate chain or by root certificate reference")
	} else if len(rootCerts) > 1 {
		return nil, nil, errors.New("one root certificate is allowed")
	}

	if len(rootCerts) == 0 {
		return intermediateCerts[len(intermediateCerts)-1:], intermediateCerts[:len(intermediateCerts)-1], nil
	}

	return rootCerts, intermediateCerts, nil
}

// trustedCert
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/pkg/cosign/verify.go#L1436
// as is.
func trustedCert(cert *x509.Certificate, roots, intermediates *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime:   cert.NotBefore,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("cert verification failed: %w. Check your TUF root (see cosign initialize) or set a custom root with env var SIGSTORE_ROOT_FILE", err)
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
