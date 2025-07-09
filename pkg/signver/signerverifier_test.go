package signver_test

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = Describe("SignerVerifier", func() {
	DescribeTable("should sign and verify",
		func(ctx SpecContext, noIntermediates, ExcludeRootFromIntermediates, useBase64Encoding bool) {
			passFunc := cryptoutils.SkipPassword

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:                     passFunc,
				TmpDir:                       GinkgoT().TempDir(),
				NoIntermediates:              noIntermediates,
				ExcludeRootFromIntermediates: ExcludeRootFromIntermediates,
				UseBase64Encoding:            useBase64Encoding,
			})

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, certGen.ChainRef, certGen.RootRef, signver.KeyOpts{
				PassFunc: passFunc,
				KeyRef:   certGen.PrivRef,
			})
			Expect(err).To(Succeed())

			message := []byte("sign me")

			sig, err := sv.SignMessage(bytes.NewReader(message))
			Expect(err).To(Succeed())

			err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
			Expect(err).To(Succeed())
		},
		// ----- certs are file paths -----
		Entry(
			"with intermediates, root cert in chain, certs are file paths",
			false,
			false,
			false,
		),
		Entry(
			"with intermediates, root cert not in chain, certs are file paths",
			false,
			true,
			false,
		),
		Entry(
			"without intermediates, root cert not in chain, certs are file paths",
			true,
			true,
			false,
		),
		// ----- certs are base64 stings -----
		Entry(
			"with intermediates, root cert in chain, certs are base64 stings",
			false,
			false,
			true,
		),
		Entry(
			"with intermediates, root cert not in chain, certs are base64 stings",
			false,
			true,
			true,
		),
		Entry(
			"without intermediates, root cert not in chain, certs are base64 stings",
			true,
			true,
			true,
		),
	)
})
