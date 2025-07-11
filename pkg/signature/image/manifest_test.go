package image_test

import (
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/image"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = Describe("manifest", func() {
	DescribeTable("sign and verify image manifest",
		func(ctx SpecContext, noIntermediates, ExcludeRootFromIntermediates, useBase64Encoding bool) {
			passFunc := cryptoutils.SkipPassword

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				PassFunc:                     passFunc,
				TmpDir:                       GinkgoT().TempDir(),
				NoIntermediates:              noIntermediates,
				ExcludeRootFromIntermediates: ExcludeRootFromIntermediates,
				UseBase64Encoding:            useBase64Encoding,
			})

			_, chainRef, err := signver.ConcatChain(certGen.IntermediatesRef, certGen.RootRef)
			Expect(err).To(Succeed())
			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, chainRef, signver.KeyOpts{
				KeyRef:   certGen.PrivRef,
				PassFunc: passFunc,
			})
			Expect(err).To(Succeed())

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

			err = image.VerifyImageManifestSignature(ctx, certGen.RootRef, manifestMutated)
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
