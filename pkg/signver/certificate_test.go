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
			_, certFile, _, _, privKey, expectedLeafCert, _, _ := cert_utils.GenerateCertificateFiles(GinkgoT().TempDir(), cryptoutils.SkipPassword, false)

			var certRef string
			if useBase64Encoding {
				certRef = readFileContentAsBase64(certFile)
			} else {
				certRef = certFile
			}

			actualLeafCert, err := signver.VerifyCert(privKey.Public(), certRef)
			Expect(err).To(Succeed())
			Expect(actualLeafCert).To(Equal(expectedLeafCert))
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
		func(useBase64Encoding, useStandaloneRootCa bool) {
			_, certFile, chainFile, rootFile, _, _, chainCerts, rootCert := cert_utils.GenerateCertificateFiles(GinkgoT().TempDir(), cryptoutils.SkipPassword, useStandaloneRootCa)

			var certRef string
			var chainRef string
			var rootRef string

			if useBase64Encoding {
				certRef = readFileContentAsBase64(certFile)
				chainRef = readFileContentAsBase64(chainFile)
				rootRef = readFileContentAsBase64(rootFile)
			} else {
				certRef = certFile
				chainRef = chainFile
				rootRef = rootFile
			}

			if !useStandaloneRootCa {
				rootRef = ""
			}

			roots, intermediates, err := signver.VerifyChain(certRef, chainRef, rootRef)
			Expect(err).To(Succeed())
			Expect(intermediates).To(HaveLen(1))
			Expect(roots).To(HaveLen(1))

			if !useStandaloneRootCa {
				Expect(intermediates[0]).To(Equal(chainCerts[0]))
				Expect(roots[0]).To(Equal(chainCerts[1]))
			} else {
				Expect(intermediates[0]).To(Equal(chainCerts[0]))
				Expect(roots[0]).To(Equal(rootCert))
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
