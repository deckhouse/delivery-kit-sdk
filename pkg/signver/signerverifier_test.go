package signver_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var _ = Describe("SignerVerifier", func() {
	DescribeTable("should sign and verify",
		func(ctx SpecContext, OptsFunc OptionsFunc) {
			passFunc := cryptoutils.SkipPassword

			keyFile, certFile, chainFile, _, _, _ := generateCertificateFiles(GinkgoT().TempDir(), passFunc)

			certNew, chainNew, koNew := OptsFunc(certFile, chainFile, signver.KeyOpts{
				KeyRef:   keyFile,
				PassFunc: passFunc,
			})

			sv, err := signver.NewSignerVerifier(ctx, certNew, chainNew, koNew)
			Expect(err).To(Succeed())

			message := []byte("sign me")

			sig, err := sv.SignMessage(bytes.NewReader(message))
			Expect(err).To(Succeed())

			err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
			Expect(err).To(Succeed())
		},
		Entry(
			"with key, cert and cert chain as file paths",
			func(certFile, chainFile string, opts signver.KeyOpts) (string, string, signver.KeyOpts) {
				return certFile, chainFile, opts
			},
		),
		Entry(
			"with key, cert and cert chain as base64",
			func(certFile, chainFile string, opts signver.KeyOpts) (string, string, signver.KeyOpts) {
				return base64.StdEncoding.EncodeToString(readFile(certFile)),
					base64.StdEncoding.EncodeToString(readFile(chainFile)),
					signver.KeyOpts{
						KeyRef:   base64.StdEncoding.EncodeToString(readFile(opts.KeyRef)),
						PassFunc: opts.PassFunc,
					}
			},
		),
	)
})

type OptionsFunc func(certFile, chainFile string, ko signver.KeyOpts) (certFileModified, chainFileModified string, koModified signver.KeyOpts)

func readFile(filePath string) []byte {
	raw, err := os.ReadFile(filePath)
	Expect(err).To(Succeed())
	return raw
}

// generateCertificateFiles
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign_test.go#L46
// as is.
func generateCertificateFiles(tmpDir string, passFunc cryptoutils.PassFunc) (privFile, certFile, chainFile string, privKey *ecdsa.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate) {
	rootCert, rootKey, _ := cert_utils.GenerateRootCa()
	subCert, subKey, _ := cert_utils.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := cert_utils.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to encode private key: %v", err))
	}
	password := []byte{}
	if passFunc != nil {
		password, err = passFunc(true)
		if err != nil {
			Expect(err).To(Succeed(), fmt.Sprintf("failed to read password: %v", err))
		}
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to encrypt key: %v", err))
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  signver.SigstorePrivateKeyPemType,
	})

	tmpPrivFile, err := os.CreateTemp(tmpDir, "sigstore_test_*.key")
	if err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp key file: %v", err))
	}
	defer tmpPrivFile.Close()
	if _, err = tmpPrivFile.Write(privBytes); err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to write key file: %v", err))
	}

	tmpCertFile, err := os.CreateTemp(tmpDir, "sigstore.crt")
	if err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp certificate file: %v", err))
	}
	defer tmpCertFile.Close()
	if _, err = tmpCertFile.Write(pemLeaf); err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to write certificate file: %v", err))
	}

	tmpChainFile, err := os.CreateTemp(tmpDir, "sigstore_chain.crt")
	if err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to create temp chain file: %v", err))
	}
	defer tmpChainFile.Close()
	pemChain := pemSub
	pemChain = append(pemChain, pemRoot...)
	if _, err = tmpChainFile.Write(pemChain); err != nil {
		Expect(err).To(Succeed(), fmt.Sprintf("failed to write chain file: %v", err))
	}

	return tmpPrivFile.Name(), tmpCertFile.Name(), tmpChainFile.Name(), privKey, leafCert, []*x509.Certificate{subCert, rootCert}
}
