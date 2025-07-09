package cert_utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

/*
To use:

rootCert, rootKey, _ := GenerateRootCa()
subCert, subKey, _ := GenerateSubordinateCa(rootCert, rootKey)
leafCert, _, _ := GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)

roots := x509.NewCertPool()
subs := x509.NewCertPool()
roots.AddCert(rootCert)
subs.AddCert(subCert)
opts := x509.VerifyOptions{
	Roots:         roots,
	Intermediates: subs,
	KeyUsages: []x509.ExtKeyUsage{
		x509.ExtKeyUsageCodeSigning,
	},
}
_, err := leafCert.Verify(opts)
*/

func createCertificate(template, parent *x509.Certificate, pub interface{}, priv crypto.Signer) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// GenerateRootCa
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/test/cert_utils.go#L65
// as is.
func GenerateRootCa() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-5 * time.Hour),
		NotAfter:              time.Now().Add(5 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(rootTemplate, rootTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// GenerateSubordinateCa
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/test/cert_utils.go#L92
// as is.
func GenerateSubordinateCa(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore-sub",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-2 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// GenerateLeafCert
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/test/cert_utils.go#L148
// as is.
func GenerateLeafCert(subject, oidcIssuer string, parentTemplate *x509.Certificate, parentPriv crypto.Signer, exts ...pkix.Extension) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	exts = append(exts, pkix.Extension{
		// OID for OIDC Issuer extension
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
		Critical: false,
		Value:    []byte(oidcIssuer),
	})
	certTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		EmailAddresses:  []string{subject},
		NotBefore:       time.Now().Add(-1 * time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:            false,
		ExtraExtensions: exts,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(certTemplate, parentTemplate, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

type GenerateCertificatesResult struct {
	PrivKey           *ecdsa.PrivateKey
	LeafCert          *x509.Certificate
	IntermediateCerts []*x509.Certificate
	RootCert          *x509.Certificate

	PrivRef          string
	LeafRef          string
	IntermediatesRef string
	RootRef          string
}

type GenerateCertificatesOptions struct {
	PassFunc                     cryptoutils.PassFunc
	TmpDir                       string
	NoIntermediates              bool
	ExcludeRootFromIntermediates bool
	UseBase64Encoding            bool
}

// GenerateCertificatesWithOptions
// Inspired with https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign_test.go#L46
func GenerateCertificatesWithOptions(options GenerateCertificatesOptions) GenerateCertificatesResult {
	rootCert, rootKey, err := GenerateRootCa()
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate root ca: %v", err))

	var subCert *x509.Certificate
	var subKey *ecdsa.PrivateKey
	var leafCert *x509.Certificate
	var privKey *ecdsa.PrivateKey

	if options.NoIntermediates {
		leafCert, privKey, err = GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to generate leaf ca: %v", err))
	} else {
		subCert, subKey, err = GenerateSubordinateCa(rootCert, rootKey)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to generate subordinate ca: %v", err))

		leafCert, privKey, err = GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to generate leaf ca: %v", err))
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to encode private key: %v", err))

	password := []byte{}
	if options.PassFunc != nil {
		password, err = options.PassFunc(true)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to read password: %v", err))
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to encrypt key: %v", err))

	privPem := pem.EncodeToMemory(&pem.Block{Bytes: encBytes, Type: signver.SigstorePrivateKeyPemType})
	leafPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	intermediatesPem := make([]byte, 0)
	rootPem := make([]byte, 0)

	result := GenerateCertificatesResult{
		PrivKey:           privKey,
		LeafCert:          leafCert,
		IntermediateCerts: make([]*x509.Certificate, 0),
	}

	switch {
	case options.NoIntermediates && options.ExcludeRootFromIntermediates:
		rootPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
		result.RootCert = rootCert
	case options.NoIntermediates && !options.ExcludeRootFromIntermediates:
		Fail(fmt.Sprintf("%+v option combination is not allowed", options))
	case !options.NoIntermediates && options.ExcludeRootFromIntermediates:
		intermediatesPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
		result.IntermediateCerts = append(result.IntermediateCerts, subCert)
		rootPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
		result.RootCert = rootCert
	case !options.NoIntermediates && !options.ExcludeRootFromIntermediates:
		intermediatesPem = append(intermediatesPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})...)
		intermediatesPem = append(intermediatesPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})...)
		result.IntermediateCerts = append(result.IntermediateCerts, subCert)
		result.IntermediateCerts = append(result.IntermediateCerts, rootCert)
	}

	if options.UseBase64Encoding {
		result.PrivRef = base64.StdEncoding.EncodeToString(privPem)
		result.LeafRef = base64.StdEncoding.EncodeToString(leafPem)
		result.IntermediatesRef = base64.StdEncoding.EncodeToString(intermediatesPem)
		result.RootRef = base64.StdEncoding.EncodeToString(rootPem)
	} else {
		Expect(options.TmpDir).NotTo(BeEmpty())
		result.PrivRef = makeFile(options.TmpDir, "sigstore_test_*.key", privPem)
		result.LeafRef = makeFile(options.TmpDir, "sigstore.crt", leafPem)
		result.IntermediatesRef = makeFile(options.TmpDir, "sigstore_chain.crt", intermediatesPem)
		result.RootRef = makeFile(options.TmpDir, "sigstore_root.crt", rootPem)
	}

	return result
}

func makeFile(tmpDir, filePattern string, fileData []byte) string {
	file, err := os.CreateTemp(tmpDir, filePattern)
	Expect(err).To(Succeed(), fmt.Sprintf("creating file with pattern %q: %v", filePattern, err))
	defer file.Close()
	_, err = file.Write(fileData)
	Expect(err).To(Succeed(), fmt.Sprintf("writing fileData %q into file %q: %v", fileData, file.Name(), err))
	return file.Name()
}
