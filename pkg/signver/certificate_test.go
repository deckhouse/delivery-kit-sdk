package signver_test

import (
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var _ = Describe("certificate", func() {
	DescribeTable("VerifyCert()",
		func(useBase64Encoding bool) {
			result := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:          cryptoutils.SkipPassword,
				TmpDir:            GinkgoT().TempDir(),
				NoIntermediates:   false,
				NoRootInChain:     false,
				UseBase64Encoding: useBase64Encoding,
			})

			leafCert, err := signver.VerifyCert(result.PrivKey.Public(), result.LeafRef)
			Expect(err).To(Succeed())
			Expect(leafCert).To(Equal(result.LeafCert))
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
		func(useBase64Encoding, noRootInChain bool) {
			result := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:          cryptoutils.SkipPassword,
				TmpDir:            GinkgoT().TempDir(),
				NoIntermediates:   false,
				NoRootInChain:     noRootInChain,
				UseBase64Encoding: useBase64Encoding,
			})

			roots, intermediates, err := signver.VerifyChain(result.LeafRef, result.ChainRef, result.RootRef)
			Expect(err).To(Succeed())

			if !noRootInChain {
				Expect(intermediates).To(HaveLen(1))
				Expect(roots).To(HaveLen(1))
				Expect(result.ChainCerts).To(HaveLen(2))
				Expect(intermediates[0]).To(Equal(result.ChainCerts[0]))
				Expect(roots[0]).To(Equal(result.ChainCerts[1]))
			} else {
				Expect(intermediates).To(HaveLen(1))
				Expect(roots).To(HaveLen(1))
				Expect(result.ChainCerts).To(HaveLen(1))
				Expect(intermediates[0]).To(Equal(result.ChainCerts[0]))
				Expect(roots[0]).To(Equal(result.RootCert))
			}
		},
		Entry(
			"with cert, chain and root as file paths AND root ca included into chain",
			false,
			false,
		),
		Entry(
			"with cert, chain and root as file paths AND standalone root ca",
			false,
			true,
		),
		Entry(
			"with cert, chain and root as base64 AND root ca included into chain",
			true,
			false,
		),
		Entry(
			"with cert, chain and root as base64 AND standalone root ca",
			true,
			true,
		),
	)
})
