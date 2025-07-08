package cert_utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

// GenerateCertificateFiles
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign_test.go#L46
// as modified after.
func GenerateCertificateFiles(tmpDir string, passFunc cryptoutils.PassFunc, excludeRootFromChain bool) (privFile, certFile, chainFile, rootFile string, privKey *ecdsa.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) {
	rootCert, rootKey, err := GenerateRootCa()
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate root ca: %v", err))

	subCert, subKey, err := GenerateSubordinateCa(rootCert, rootKey)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate subordinate ca: %v", err))

	leafCert, privKey, err := GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate leaf ca: %v", err))

	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to encode private key: %v", err))

	password := []byte{}
	if passFunc != nil {
		password, err = passFunc(true)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to read password: %v", err))
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to encrypt key: %v", err))

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  signver.SigstorePrivateKeyPemType,
	})

	tmpPrivFile, err := os.CreateTemp(tmpDir, "sigstore_test_*.key")
	Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp key file: %v", err))

	defer tmpPrivFile.Close()
	_, err = tmpPrivFile.Write(privBytes)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to write key file: %v", err))

	tmpCertFile, err := os.CreateTemp(tmpDir, "sigstore.crt")
	Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp certificate file: %v", err))

	defer tmpCertFile.Close()
	_, err = tmpCertFile.Write(pemLeaf)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to write certificate file: %v", err))

	tmpChainFile, err := os.CreateTemp(tmpDir, "sigstore_chain.crt")
	Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp chain file: %v", err))
	defer tmpChainFile.Close()

	tmpRootFile, err := os.CreateTemp(tmpDir, "sigstore_root.crt")
	Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp root file: %v", err))
	defer tmpRootFile.Close()
	_, err = tmpRootFile.Write(pemRoot)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to write root file: %v", err))

	pemChain := pemSub

	if excludeRootFromChain {
		_, err = tmpChainFile.Write(pemChain)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to write chain file: %v", err))

		return tmpPrivFile.Name(), tmpCertFile.Name(), tmpChainFile.Name(), tmpRootFile.Name(), privKey, leafCert, []*x509.Certificate{subCert}, rootCert
	} else {
		pemChain = append(pemChain, pemRoot...)
		_, err = tmpChainFile.Write(pemChain)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to write chain file: %v", err))

		return tmpPrivFile.Name(), tmpCertFile.Name(), tmpChainFile.Name(), tmpRootFile.Name(), privKey, leafCert, []*x509.Certificate{subCert, rootCert}, nil
	}
}
