package image_test

import (
	"context"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/image"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("manifest", func() {
	//DescribeTable("sign and verify image manifest",
	//	func(ctx SpecContext, noIntermediates, ExcludeRootFromIntermediates, useBase64Encoding bool) {
	//		passFunc := cryptoutils.SkipPassword
	//
	//		certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
	//			PassFunc:                     passFunc,
	//			TmpDir:                       GinkgoT().TempDir(),
	//			NoIntermediates:              noIntermediates,
	//			ExcludeRootFromIntermediates: ExcludeRootFromIntermediates,
	//			UseBase64Encoding:            useBase64Encoding,
	//		})
	//
	//		_, chainRef, err := signver.ConcatChain(certGen.IntermediatesRef, certGen.RootRef)
	//		Expect(err).To(Succeed())
	//		sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, chainRef, signver.KeyOpts{
	//			KeyRef:   certGen.PrivRef,
	//			PassFunc: passFunc,
	//		})
	//		Expect(err).To(Succeed())
	//
	//		test(ctx, sv, certGen.RootRef)
	//	},
	//	// ----- certs are file paths -----
	//	Entry(
	//		"with intermediates, root cert in chain, certs are file paths",
	//		false,
	//		false,
	//		false,
	//	),
	//	Entry(
	//		"with intermediates, root cert not in chain, certs are file paths",
	//		false,
	//		true,
	//		false,
	//	),
	//	Entry(
	//		"without intermediates, root cert not in chain, certs are file paths",
	//		true,
	//		true,
	//		false,
	//	),
	//	// ----- certs are base64 stings -----
	//	Entry(
	//		"with intermediates, root cert in chain, certs are base64 stings",
	//		false,
	//		false,
	//		true,
	//	),
	//	Entry(
	//		"with intermediates, root cert not in chain, certs are base64 stings",
	//		false,
	//		true,
	//		true,
	//	),
	//	Entry(
	//		"without intermediates, root cert not in chain, certs are base64 stings",
	//		true,
	//		true,
	//		true,
	//	),
	//)
	//
	//It("with intermediates, root cert in chain, certs are file paths", func() {
	//	sv, err := signver.NewSignerVerifier(context.Background(), cert_utils.SignerCertBase64, cert_utils.SignerChainBase64, signver.KeyOpts{
	//		KeyRef:   cert_utils.SignerKeyBase64,
	//	})
	//	Expect(err).To(Succeed())
	//
	//	test(context.Background(), sv, cert_utils.RootCABase64)
	//})

	It("with intermediates, root cert in chain, certs are file paths", func() {
		sv, err := signver.NewSignerVerifier(
			context.Background(),
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMyVENDQW91Z0F3SUJBZ0lVVUdLZDkyUkJGQ3dYL3Jla3ZsTE5taTRJd3pJd0JRWURLMlZ3TUhzeEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SSXdFQVlEVlFRTEV3bEVaV05yYUc5MWMyVXhJakFnQmdOVkJBTVRHVXBUClF5QkdiR0Z1ZENCSmJuUmxjbTFsWkdsaGRHVWdRMEV3SGhjTk1qVXdOekl4TVRNek5UQXhXaGNOTWpZd09ESXcKTVRNek5UTXhXakI0TVFzd0NRWURWUVFHRXdKU1ZURVBNQTBHQTFVRUNCTUdUVzl6WTI5M01ROHdEUVlEVlFRSApFd1pOYjNOamIzY3hFakFRQmdOVkJBb1RDVXBUUXlCR2JHRnVkREVTTUJBR0ExVUVDeE1KUkdWamEyaHZkWE5sCk1SOHdIUVlEVlFRRERCWmthQzF6YVdkdVpYSkFaR1ZqYTJodmRYTmxMbkoxTUNvd0JRWURLMlZ3QXlFQXpMWmQKajRtTnNvUkFFeFlmV3dWdExtdHpWWjRxekRIUmhVbVJDVEJrMDJDamdnRWlNSUlCSGpBT0JnTlZIUThCQWY4RQpCQU1DQTZnd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNNQjBHQTFVZERnUVdCQlQ2CkxubGtjMkRobythZFg0YjFjYk11VXBQSnBUQWZCZ05WSFNNRUdEQVdnQlFXSWdlNW83NjFqakE5VEZzaGhsVWUKR3duUDZ6QkpCZ2dyQmdFRkJRY0JBUVE5TURzd09RWUlLd1lCQlFVSE1BS0dMV2gwZEhCek9pOHZNVEkzTGpBdQpNQzR4T2pneU1EQXZkakV2Y0d0cExXWnNZVzUwTFdsdWRDMWthQzlqWVRBaEJnTlZIUkVFR2pBWWdSWmthQzF6CmFXZHVaWEpBWkdWamEyaHZkWE5sTG5KMU1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEJ6T2k4dk1USTMKTGpBdU1DNHhPamd5TURBdmRqRXZjR3RwTFdac1lXNTBMV2x1ZEMxa2FDOWpjbXd3QlFZREsyVndBMEVBSGNseApCamF0aVVDOEN3SnNWalE4RUVrdHIwYVlQNnBNc0dDL3QrWkhMWUJSOVk3UmhxclFvb3lNVE5URXFnbE43REp5ClRuQ2I0U21yTEY0YnpmZDdDQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvakNDQWxTZ0F3SUJBZ0lVWmNiNE9WTmhhbXJOTU53dlRFT1J5RGFJMHhjd0JRWURLMlZ3TUhneEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SQXdEZ1lEVlFRTEV3ZEpibVp2YzJWak1TRXdId1lEVlFRREV4aEtVME1nClJteGhiblFnVW05dmRDQkRRU0JCTFRJd01qVXdIaGNOTWpVd056SXhNVE16TXpVeldoY05NelV3TnpFNU1UTXoKTkRJeldqQjdNUXN3Q1FZRFZRUUdFd0pTVlRFUE1BMEdBMVVFQ0JNR1RXOXpZMjkzTVE4d0RRWURWUVFIRXdaTgpiM05qYjNjeEVqQVFCZ05WQkFvVENVcFRReUJHYkdGdWRERVNNQkFHQTFVRUN4TUpSR1ZqYTJodmRYTmxNU0l3CklBWURWUVFERXhsS1UwTWdSbXhoYm5RZ1NXNTBaWEp0WldScFlYUmxJRU5CTUNvd0JRWURLMlZ3QXlFQTYyeG4KcVJEUm5uSGZDRXJlNFliYW55aDNDT2p6Z3N1alFSenJGSlVtS2Ztamdld3dnZWt3RGdZRFZSMFBBUUgvQkFRRApBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkJZaUI3bWp2cldPTUQxTVd5R0dWUjRiCkNjL3JNQjhHQTFVZEl3UVlNQmFBRkpCZ0s0NjYzVVdZMEhKbTVGb1plK1Rsem1mek1FY0dDQ3NHQVFVRkJ3RUIKQkRzd09UQTNCZ2dyQmdFRkJRY3dBb1lyYUhSMGNITTZMeTh4TWpjdU1DNHdMakU2T0RJd01DOTJNUzl3YTJrdApabXhoYm5RdGNtOXZkQzlqWVRBOUJnTlZIUjhFTmpBME1ES2dNS0F1aGl4b2RIUndjem92THpFeU55NHdMakF1Ck1UbzRNakF3TDNZeEwzQnJhUzFtYkdGdWRDMXliMjkwTDJOeWJEQUZCZ01yWlhBRFFRQnNOZWNUU0l6bmxvQWYKYkViU2JERlpGb20wMXc2WDN5WVpqVmFOQngrNEZmV3JNZ1ppU05rM3NkZ0dNRlpEVnVaZWl4OXlQUTk3bVIzWgpaTXU0Q3JRUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
			signver.KeyOpts{
				KeyRef: "hashivault://dh-2025-july",
			},
		)
		Expect(err).To(Succeed())
		
		test(context.Background(), sv, "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNGVENDQWNlZ0F3SUJBZ0lVZElhblV0Nk0vNnFTL0RzMXJWSjZoc09JTmYwd0JRWURLMlZ3TUhneEN6QUoKQmdOVkJBWVRBbEpWTVE4d0RRWURWUVFJRXdaTmIzTmpiM2N4RHpBTkJnTlZCQWNUQmsxdmMyTnZkekVTTUJBRwpBMVVFQ2hNSlNsTkRJRVpzWVc1ME1SQXdEZ1lEVlFRTEV3ZEpibVp2YzJWak1TRXdId1lEVlFRREV4aEtVME1nClJteGhiblFnVW05dmRDQkRRU0JCTFRJd01qVXdIaGNOTWpVd056SXhNVE15TkRVMFdoY05ORFV3TnpFMk1UTXkKTlRJMFdqQjRNUXN3Q1FZRFZRUUdFd0pTVlRFUE1BMEdBMVVFQ0JNR1RXOXpZMjkzTVE4d0RRWURWUVFIRXdaTgpiM05qYjNjeEVqQVFCZ05WQkFvVENVcFRReUJHYkdGdWRERVFNQTRHQTFVRUN4TUhTVzVtYjNObFl6RWhNQjhHCkExVUVBeE1ZU2xORElFWnNZVzUwSUZKdmIzUWdRMEVnUVMweU1ESTFNQ293QlFZREsyVndBeUVBbGd1Q3hQRHUKV1VhajZjazZHdFIrZGdCNS9SRENSNmdhSWkzN3ZCQmx0ZE9qWXpCaE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUApCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCU1FZQ3VPdXQxRm1OQnladVJhR1h2azVjNW44ekFmCkJnTlZIU01FR0RBV2dCU1FZQ3VPdXQxRm1OQnladVJhR1h2azVjNW44ekFGQmdNclpYQURRUUJxbTd5S21mVG0KV01PcFdHRldxSVJLcmJnRW44NkpyQmVWSXFXakVUMWs2NEVjR2pFN0JkdWxqdjdDVGhCQ2xwY1c3bzFuUGlVeApZeDFUNnMvSmU3b0kKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=")
	})
})

func test(ctx context.Context, sv *signver.SignerVerifier, rootRef string) {
	imageRef := "nginx:latest"

	ref, err := name.ParseReference(imageRef)
	Expect(err).To(Succeed())

	desc, err := remote.Get(ref)
	Expect(err).To(Succeed())

	imgOriginal, err := desc.Image()
	Expect(err).To(Succeed())

	manifestOriginal, err := imgOriginal.Manifest()
	Expect(err).To(Succeed())

	sigAnnotations, err := image.GetSignatureAnnotationsForImageManifest(ctx, sv, manifestOriginal)
	Expect(err).To(Succeed())

	imgMutated := mutate.Annotations(imgOriginal, sigAnnotations).(v1.Image)
	Expect(err).To(Succeed())

	manifestMutated, err := imgMutated.Manifest()
	Expect(err).To(Succeed())

	err = image.VerifyImageManifestSignature(ctx, rootRef, manifestMutated)
	Expect(err).To(Succeed())
}
