package signver_test

import (
	"bytes"
	"encoding/base64"
	"os"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var _ = Describe("SignerVerifier", func() {
	DescribeTable("should sign and verify",
		func(ctx SpecContext, OptsFunc OptionsFunc) {
			passFunc := cryptoutils.SkipPassword

			keyFile, certFile, chainFile, _, _, _, _, _ := cert_utils.GenerateCertificateFiles(GinkgoT().TempDir(), passFunc, false)

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
