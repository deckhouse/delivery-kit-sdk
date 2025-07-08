package signver_test

import (
	"bytes"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var _ = Describe("SignerVerifier", func() {
	DescribeTable("should sign and verify",
		func(ctx SpecContext, useBase64Encoding bool) {
			passFunc := cryptoutils.SkipPassword

			result := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:          passFunc,
				TmpDir:            GinkgoT().TempDir(),
				NoIntermediates:   false,
				NoRootInChain:     false,
				UseBase64Encoding: useBase64Encoding,
			})

			sv, err := signver.NewSignerVerifier(ctx, result.LeafRef, result.ChainRef, signver.KeyOpts{
				PassFunc: passFunc,
				KeyRef:   result.PrivRef,
			})
			Expect(err).To(Succeed())

			message := []byte("sign me")

			sig, err := sv.SignMessage(bytes.NewReader(message))
			Expect(err).To(Succeed())

			err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
			Expect(err).To(Succeed())
		},
		Entry(
			"with key, cert and cert chain as file paths",
			false,
		),
		Entry(
			"with key, cert and cert chain as base64",
			true,
		),
	)
})
