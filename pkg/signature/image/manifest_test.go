package image_test

import (
	"context"

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
		func(ctx SpecContext, keyType cert_utils.KeyType, noIntermediates, ExcludeRootFromIntermediates, useBase64Encoding bool) {
			passFunc := cryptoutils.SkipPassword

			certGen := cert_utils.GenerateCertificatesWithOptions(cert_utils.GenerateCertificatesOptions{
				KeyType:                      keyType,
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

			imgOriginal, sigAnnotations := testSign(ctx, sv)
			testVerify(ctx, imgOriginal, sigAnnotations, certGen.RootRef)
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
			"key_type=ECDSA_P256, without intermediates, root cert not in chain, certs are file paths",
			cert_utils.KeyType_ECDSA_P256,
			true,
			true,
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
			"key_type=ED25519, without intermediates, root cert not in chain, certs are file paths",
			cert_utils.KeyType_ED25519,
			true,
			true,
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
			"key_type=ECDSA_P256, without intermediates, root cert not in chain, certs are base64 stings",
			cert_utils.KeyType_ECDSA_P256,
			true,
			true,
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
			"key_type=ED25519, without intermediates, root cert not in chain, certs are base64 stings",
			cert_utils.KeyType_ED25519,
			true,
			true,
			true,
		),
	)
})

func testSign(ctx context.Context, sv *signver.SignerVerifier) (v1.Image, map[string]string) {
	imageRef := "alpine:3.19"

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

	return imgOriginal, sigAnnotations
}

func testVerify(ctx context.Context, imgOriginal v1.Image, sigAnnotations map[string]string, rootRef string) {
	imgMutated := mutate.Annotations(imgOriginal, sigAnnotations).(v1.Image)

	manifestMutated, err := imgMutated.Manifest()
	Expect(err).To(Succeed())

	err = image.VerifyImageManifestSignature(ctx, rootRef, manifestMutated)
	Expect(err).To(Succeed())
}
