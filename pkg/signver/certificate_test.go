package signver_test

import (
	"crypto/x509"
	"slices"

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
		func(noIntermediates, useBase64Encoding bool) {
			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:          cryptoutils.SkipPassword,
				TmpDir:            GinkgoT().TempDir(),
				NoIntermediates:   noIntermediates,
				UseBase64Encoding: useBase64Encoding,
			})

			roots, intermediates, err := signver.VerifyChain(certGen.LeafRef, certGen.ChainRef)
			Expect(err).To(Succeed())

			Expect(roots).To(HaveExactElements([]*x509.Certificate{certGen.RootCert})) // only one root cert
			Expect(intermediates).To(HaveExactElements(certGen.IntermediateCerts))     // 0 or more intermediates
			Expect(slices.Concat(intermediates, roots)).To(HaveExactElements(certGen.ChainCerts))
		},
		// ----- certs are file paths -----
		Entry(
			"with intermediates, certs are file paths",
			false,
			false,
		),
		Entry(
			"without intermediates, certs are file paths",
			true,
			false,
		),
		// ----- certs are base64 stings -----
		Entry(
			"with intermediates, certs are base64 stings",
			false,
			true,
		),
		Entry(
			"without intermediates, certs are base64 stings",
			true,
			true,
		),
	)

	DescribeTable("ConcatChain()",
		func(noIntermediates bool) {
			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:        cryptoutils.SkipPassword,
				TmpDir:          GinkgoT().TempDir(),
				NoIntermediates: noIntermediates,
			})

			chainCerts, chainRef, err := signver.ConcatChain(certGen.IntermediatesRef, certGen.RootRef)
			Expect(err).To(Succeed())
			Expect(chainCerts).To(HaveExactElements(certGen.ChainCerts))
			Expect(chainRef).NotTo(Equal(certGen.ChainRef))
		},
		Entry(
			"with intermediates",
			false,
		),
		Entry(
			"without intermediates",
			true,
		),
	)
})
