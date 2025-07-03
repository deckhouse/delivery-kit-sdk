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

func VerifyCert(pk crypto.PublicKey, certRef string) ([]byte, *x509.Certificate, error) {
	// Allow both DER and PEM encoding
	certBytes, err := blob.LoadBase64OrFile(certRef)
	if err != nil {
		return []byte{}, nil, fmt.Errorf("read certificate: %w", err)
	}
	// Handle PEM
	if bytes.HasPrefix(certBytes, []byte("-----")) {
		decoded, _ := pem.Decode(certBytes)
		if decoded.Type != "CERTIFICATE" {
			return []byte{}, nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certRef)
		}
		certBytes = decoded.Bytes
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return []byte{}, nil, fmt.Errorf("parse x509 certificate: %w", err)
	}
	if cryptoutils.EqualKeys(pk, cert.PublicKey) != nil {
		return []byte{}, nil, errors.New("public key in certificate does not match the provided public key")
	}
	return certBytes, cert, nil
}

func VerifyChain(leafCert *x509.Certificate, certChainRef string) ([]byte, error) {
	// Accept only PEM encoded certificate chain
	certChainBytes, err := blob.LoadBase64OrFile(certChainRef)
	if err != nil {
		return nil, fmt.Errorf("reading certificate chain from path: %w", err)
	}
	certChain, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certChainBytes))
	if err != nil {
		return nil, fmt.Errorf("loading certificate chain: %w", err)
	}
	if len(certChain) == 0 {
		return nil, errors.New("no certificates in certificate chain")
	}
	// Verify certificate chain is valid
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certChain[len(certChain)-1])
	subPool := x509.NewCertPool()
	for _, c := range certChain[:len(certChain)-1] {
		subPool.AddCert(c)
	}
	if _, err := trustedCert(leafCert, rootPool, subPool); err != nil {
		return nil, fmt.Errorf("unable to validate certificate chain: %w", err)
	}
	// Verify SCT if present in the leaf certificate.
	contains, err := containsSCT(leafCert.Raw)
	if err != nil {
		return nil, err
	}
	if contains {
		return nil, errors.New("verification of embedded SCT is unsupported")
	}
	return certChainBytes, nil
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
