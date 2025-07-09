package signver_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = Describe("certificate", func() {
	DescribeTable("VerifyCert()",
		func(useBase64Encoding bool) {
			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:          cryptoutils.SkipPassword,
				TmpDir:            GinkgoT().TempDir(),
				UseBase64Encoding: useBase64Encoding,
			})

			leafCert, err := signver.VerifyCert(certGen.PrivKey.Public(), certGen.LeafRef)
			Expect(err).To(Succeed())
			Expect(leafCert).To(Equal(certGen.LeafCert))
		},
		Entry(
			"with cert as file path",
			false,
		),
		Entry(
			"with cert as base64 string",
			true,
		),
	)

	DescribeTable("VerifyChain()",
		func(noIntermediates, ExcludeRootFromIntermediates, useBase64Encoding bool) {
			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:                     cryptoutils.SkipPassword,
				TmpDir:                       GinkgoT().TempDir(),
				NoIntermediates:              noIntermediates,
				ExcludeRootFromIntermediates: ExcludeRootFromIntermediates,
				UseBase64Encoding:            useBase64Encoding,
			})

			roots, intermediates, err := signver.VerifyChain(certGen.LeafRef, certGen.ChainRef, certGen.RootRef)
			Expect(err).To(Succeed())

			Expect(roots).To(HaveLen(1))

			switch {
			case noIntermediates && ExcludeRootFromIntermediates:
				Expect(intermediates).To(HaveLen(0))
				Expect(roots[0]).To(Equal(certGen.RootCert))
			case noIntermediates && !ExcludeRootFromIntermediates:
				Fail("not allowed")
			case !noIntermediates && ExcludeRootFromIntermediates:
				Expect(intermediates).To(HaveLen(1))
				Expect(intermediates[0]).To(Equal(certGen.ChainCerts[0]))
				Expect(roots[0]).To(Equal(certGen.RootCert))
			case !noIntermediates && !ExcludeRootFromIntermediates:
				Expect(intermediates).To(HaveLen(1))
				Expect(intermediates[0]).To(Equal(certGen.ChainCerts[0]))
				Expect(roots[0]).To(Equal(certGen.ChainCerts[1]))
			}
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
