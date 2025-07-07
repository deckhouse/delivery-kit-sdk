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

			keyFile, certFile, chainFile, _, _, _, _, _ := generateCertificateFiles(GinkgoT().TempDir(), passFunc, false)

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
				return readFileContentAsBase64(certFile), readFileContentAsBase64(chainFile),
					signver.KeyOpts{
						KeyRef:   readFileContentAsBase64(opts.KeyRef),
						PassFunc: opts.PassFunc,
					}
			},
		),
	)
})

type OptionsFunc func(certFile, chainFile string, ko signver.KeyOpts) (certFileModified, chainFileModified string, koModified signver.KeyOpts)

func readFileContentAsBase64(filePath string) string {
	raw, err := os.ReadFile(filePath)
	Expect(err).To(Succeed())
	return base64.StdEncoding.EncodeToString(raw)
}

// generateCertificateFiles
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign_test.go#L46
// as modified after.
func generateCertificateFiles(tmpDir string, passFunc cryptoutils.PassFunc, excludeRootFromChain bool) (privFile, certFile, chainFile, rootFile string, privKey *ecdsa.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) {
	rootCert, rootKey, err := cert_utils.GenerateRootCa()
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate root ca: %v", err))

	subCert, subKey, err := cert_utils.GenerateSubordinateCa(rootCert, rootKey)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to generate subordinate ca: %v", err))

	leafCert, privKey, err := cert_utils.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
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
