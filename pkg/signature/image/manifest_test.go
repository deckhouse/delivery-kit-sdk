package image_test

import (
	"context"
	"maps"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
		func(ctx SpecContext, keyType cert_utils.KeyType, noIntermediates, noRootInChain, useBase64Encoding bool) {
			passFunc := cryptoutils.SkipPassword

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				KeyType:           keyType,
				PassFunc:          passFunc,
				TmpDir:            GinkgoT().TempDir(),
				NoIntermediates:   noIntermediates,
				NoRootInChain:     noRootInChain,
				UseBase64Encoding: useBase64Encoding,
			})

			sv, err := signver.NewSignerVerifier(ctx, certGen.LeafRef, certGen.ChainRef, signver.KeyOpts{
				KeyRef:   certGen.PrivRef,
				PassFunc: passFunc,
			})
			Expect(err).To(Succeed())

			manifest := testSign(ctx, sv)
			testVerify(ctx, manifest, []string{certGen.RootRef})
		},
		// ----- key_type=ECDSA_P256, certs are file paths -----
		Entry(
			"key_type=ECDSA_P256, with intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
			false,
			false,
			false,
		),
		Entry(
			"key_type=ECDSA_P256, with intermediates, root cert not in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
			false,
			true,
			false,
		),
		Entry(
			"key_type=ECDSA_P256, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
			true,
			false,
			false,
		),
		// ----- key_type=ED25519, certs are file paths -----
		Entry(
			"key_type=ED25519, with intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
			false,
			false,
			false,
		),
		Entry(
			"key_type=ED25519, with intermediates, root cert not in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
			false,
			true,
			false,
		),
		Entry(
			"key_type=ED25519, without intermediates, root cert in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
			true,
			false,
			false,
		),
		// ----- key_type=ECDSA_P256, certs are base64 stings -----
		Entry(
			"key_type=ECDSA_P256, with intermediates, root cert in chain, certs are base64 stings",
			cert_utils.KeyType_ECDSA_P256,
			false,
			false,
			true,
		),
		Entry(
			"key_type=ECDSA_P256, with intermediates, root cert not in chain, certs are base64 stings",
			cert_utils.KeyType_ECDSA_P256,
			false,
			true,
			true,
		),
		Entry(
			"key_type=ECDSA_P256, without intermediates, root cert in chain, certs are base64 stings",
			cert_utils.KeyType_ECDSA_P256,
			true,
			false,
			true,
		),
		// ----- key_type=KeyType_ED25519, certs are base64 stings -----
		Entry(
			"key_type=ED25519, with intermediates, root cert in chain, certs are base64 stings",
			cert_utils.KeyType_ED25519,
			false,
			false,
			true,
		),
		Entry(
			"key_type=ED25519, with intermediates, root cert not in chain, certs are base64 stings",
			cert_utils.KeyType_ED25519,
			false,
			true,
			true,
		),
		Entry(
			"key_type=ED25519, without intermediates, root cert in chain, certs are base64 stings",
			cert_utils.KeyType_ED25519,
			true,
			false,
			true,
		),
	)

	DescribeTable("verify image manifest with several different root certificates",
		func(ctx SpecContext, generationCount, generationSelectionIndex int) {
			passFunc := cryptoutils.SkipPassword

			certGens := make([]cert_utils.GenerateCertificatesResult, generationCount)
			rootRefs := make([]string, generationCount)

			for i := 0; i < generationCount; i++ {
				certGens[i] = cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
					PassFunc:      passFunc,
					TmpDir:        GinkgoT().TempDir(),
					NoRootInChain: true,
				})
				rootRefs[i] = certGens[i].RootRef
			}

			selectedCertGen := certGens[generationSelectionIndex]

			sv, err := signver.NewSignerVerifier(ctx, selectedCertGen.LeafRef, selectedCertGen.ChainRef, signver.KeyOpts{
				KeyRef:   selectedCertGen.PrivRef,
				PassFunc: passFunc,
			})
			Expect(err).To(Succeed())

			manifest := testSign(ctx, sv)
			testVerify(ctx, manifest, rootRefs)
		},
		Entry(
			"with generation_count=3, generation_selection_index=1",
			3,
			1,
		),
	)
})

func testSign(ctx context.Context, sv *signver.SignerVerifier) *v1.Manifest {
	imageRef := "alpine:3.19"

	ref, err := name.ParseReference(imageRef)
	Expect(err).To(Succeed())

	desc, err := remote.Get(ref)
	Expect(err).To(Succeed())

	imgOriginal, err := desc.Image()
	Expect(err).To(Succeed())

	manifest, err := imgOriginal.Manifest()
	Expect(err).To(Succeed())

	sigAnnotations, err := image.GetSignatureAnnotationsForImageManifest(ctx, sv, manifest)
	Expect(err).To(Succeed())

	maps.Copy(manifest.Annotations, sigAnnotations)

	return manifest
}

func testVerify(ctx context.Context, manifest *v1.Manifest, rootRefs []string) {
	err := image.VerifyImageManifestSignature(ctx, rootRefs, manifest)
	Expect(err).To(Succeed())
}
