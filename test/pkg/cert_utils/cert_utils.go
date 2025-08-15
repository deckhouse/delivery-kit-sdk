package cert_utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

func createCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	Expect(err).To(Succeed())

	cert, err := x509.ParseCertificate(certBytes)
	Expect(err).To(Succeed())
	return cert, nil
}

// generateRootCa
// Inspired with https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/test/cert_utils.go#L65
func generateRootCa(keyType KeyType) (*x509.Certificate, crypto.Signer, error) {
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

	priv, err := generateKey(keyType)
	Expect(err).To(Succeed())

	cert, err := createCertificate(rootTemplate, rootTemplate, priv.Public(), priv)
	Expect(err).To(Succeed())

	return cert, priv, nil
}

// generateSubordinateCa
// Inspired with https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/test/cert_utils.go#L92
func generateSubordinateCa(keyType KeyType, rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
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

	priv, err := generateKey(keyType)
	Expect(err).To(Succeed())

	cert, err := createCertificate(subTemplate, rootTemplate, priv.Public(), rootPriv)
	Expect(err).To(Succeed())

	return cert, priv, nil
}

// generateLeafCert
// Inspired with https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/test/cert_utils.go#L148
func generateLeafCert(keyType KeyType, subject, oidcIssuer string, parentTemplate *x509.Certificate, parentPriv crypto.Signer, exts ...pkix.Extension) (*x509.Certificate, crypto.Signer, error) {
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

	priv, err := generateKey(keyType)
	Expect(err).To(Succeed())

	cert, err := createCertificate(certTemplate, parentTemplate, priv.Public(), parentPriv)
	Expect(err).To(Succeed())

	return cert, priv, nil
}

func generateKey(keyType KeyType) (crypto.Signer, error) {
	switch keyType {
	case KeyType_ECDSA_P256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyType_ED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		panic(fmt.Sprintf("unsupported key type: %s", keyType))
	}
}

type GenerateCertificatesResult struct {
	PrivKey           crypto.Signer
	LeafCert          *x509.Certificate
	IntermediateCerts []*x509.Certificate
	RootCert          *x509.Certificate
	ChainCerts        []*x509.Certificate

	PrivRef          string
	LeafRef          string
	IntermediatesRef string
	RootRef          string
	ChainRef         string
}

type GenerateCertificatesOptions struct {
	KeyType           KeyType
	PassFunc          cryptoutils.PassFunc
	TmpDir            string
	NoIntermediates   bool
	NoRootInChain     bool
	UseBase64Encoding bool
}

// GenerateCertificatesWithOptions
// Inspired with https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign_test.go#L46
func GenerateCertificatesWithOptions(options GenerateCertificatesOptions) GenerateCertificatesResult {
	rootCert, rootKey, err := generateRootCa(options.KeyType)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate root ca: %v", err))

	var subCert *x509.Certificate
	var subKey crypto.Signer
	var leafCert *x509.Certificate
	var privKey crypto.Signer

	if options.NoIntermediates {
		leafCert, privKey, err = generateLeafCert(options.KeyType, "subject", "oidc-issuer", rootCert, rootKey)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to generate leaf ca: %v", err))
	} else {
		subCert, subKey, err = generateSubordinateCa(options.KeyType, rootCert, rootKey)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to generate subordinate ca: %v", err))

		leafCert, privKey, err = generateLeafCert(options.KeyType, "subject", "oidc-issuer", subCert, subKey)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to generate leaf ca: %v", err))
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to encode private key: %v", err))

	var password []byte
	if options.PassFunc != nil {
		password, err = options.PassFunc(true)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to read password: %v", err))
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to encrypt key: %v", err))

	privPem := pem.EncodeToMemory(&pem.Block{Bytes: encBytes, Type: signver.SigstorePrivateKeyPemType})
	leafPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	intermediatesPem := make([]byte, 0)
	rootPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	chainPem := make([]byte, 0)

	result := GenerateCertificatesResult{
		PrivKey:           privKey,
		LeafCert:          leafCert,
		IntermediateCerts: make([]*x509.Certificate, 0),
		RootCert:          rootCert,
		ChainCerts:        make([]*x509.Certificate, 0),
	}

	if !options.NoIntermediates {
		intermediatesPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
		result.IntermediateCerts = append(result.IntermediateCerts, subCert)
		chainPem = append(chainPem, intermediatesPem...)
		result.ChainCerts = append(result.ChainCerts, result.IntermediateCerts...)
	}

	if !options.NoRootInChain {
		chainPem = append(chainPem, rootPem...)
		result.ChainCerts = append(result.ChainCerts, result.RootCert)
	}

	if options.UseBase64Encoding {
		result.PrivRef = base64.StdEncoding.EncodeToString(privPem)
		result.LeafRef = base64.StdEncoding.EncodeToString(leafPem)
		result.IntermediatesRef = base64.StdEncoding.EncodeToString(intermediatesPem)
		result.RootRef = base64.StdEncoding.EncodeToString(rootPem)
		result.ChainRef = base64.StdEncoding.EncodeToString(chainPem)
	} else {
		Expect(options.TmpDir).NotTo(BeEmpty())
		result.PrivRef = MakeFile(options.TmpDir, "sigstore_*.pem.key", privPem)
		result.LeafRef = MakeFile(options.TmpDir, "sigstore_*.pem.crt", leafPem)
		result.IntermediatesRef = MakeFile(options.TmpDir, "sigstore_intermediates_*.pem.crt", intermediatesPem)
		result.RootRef = MakeFile(options.TmpDir, "sigstore_root_*.pem.crt", rootPem)
		result.ChainRef = MakeFile(options.TmpDir, "sigstore_chain_*.pem.crt", chainPem)
	}

	return result
}

func MakeFile(tmpDir, filePattern string, fileData []byte) string {
	file, err := os.CreateTemp(tmpDir, filePattern)
	Expect(err).To(Succeed(), fmt.Sprintf("creating file with pattern %q: %v", filePattern, err))
	defer file.Close()
	_, err = file.Write(fileData)
	Expect(err).To(Succeed(), fmt.Sprintf("writing fileData %q into file %q: %v", fileData, file.Name(), err))
	return file.Name()
}
