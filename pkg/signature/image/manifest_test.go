package image_test

import (
	"bytes"
	_ "embed"
	"maps"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/image"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

//go:embed testdata/manifest_spec_sample.json
var manifestSampleContent []byte

var _ = Describe("manifest", func() {
	DescribeTable("sign and verify manifest",
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
				KeyRef:   certGen.PrivRef,
				PassFunc: passFunc,
			})
			Expect(err).To(Succeed())

			// Copied from https://github.com/opencontainers/image-spec/blob/v1.0.1/manifest.md#example-image-manifest
			manifest, err := v1.ParseManifest(bytes.NewReader(manifestSampleContent))
			Expect(err).To(Succeed())

			sigAnnotations, err := image.GetSignatureAnnotationsForImageManifest(ctx, sv, manifest)
			Expect(err).To(Succeed())

			maps.Copy(manifest.Annotations, sigAnnotations)

			err = image.VerifyImageManifestSignature(ctx, certGen.RootRef, manifest)
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
