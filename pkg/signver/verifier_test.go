package signver_test

import (
	"bytes"
	"encoding/base64"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var _ = Describe("Verifier", func() {
	DescribeTable("verify signature",
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

			verifier, err := signver.NewVerifierFromCert(ctx, certNew)
			Expect(err).To(Succeed())

			err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
			Expect(err).To(Succeed())
		},
		Entry(
			"with cert as file path",
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
