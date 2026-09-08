package inhouse_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

const (
	helloTxtFile                      = "../../../../test/data/hello.txt"
	helloElfFile                      = "../../../../test/data/hello.elf"
	helloElfFileWithSignature         = "../../../../test/data/hello_with_signature.elf"
	helloElfFileWithOutdatedSignature = "../../../../test/data/hello_with_outdated_signature.elf"
	helloSectionlessElfFile           = "../../../../test/data/hello_sectionless.elf"
)

var _ = Describe("signature/elf/custom", func() {
	DescribeTable("should add new signature",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldElfBinary := readFile(helloElfFile)
			newElfFilePath, cleanupTmpFile := makeTempFileCopy(helloElfFile)
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newElfFilePath)).To(Succeed())

			newElfBinary := readFile(newElfFilePath)

			Expect(newElfBinary).NotTo(Equal(oldElfBinary))
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, newElfFilePath)).To(Succeed())
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should update outdated signature",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldElfBinary := readFile(helloElfFileWithOutdatedSignature)
			newElfFilePath, cleanupTmpFile := makeTempFileCopy(helloElfFileWithOutdatedSignature)
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newElfFilePath)).To(Succeed())

			newElfBinary := readFile(newElfFilePath)

			Expect(newElfBinary).NotTo(Equal(oldElfBinary))
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, newElfFilePath)).To(Succeed())
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to sign non-elf file",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldTxtData := readFile(helloTxtFile)
			newTxtFilePath, cleanupTmpFile := makeTempFileCopy(helloTxtFile)
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newTxtFilePath)).To(Equal(elf.ErrNotELF))

			newTxtData := readFile(newTxtFilePath)
			Expect(newTxtData).To(Equal(oldTxtData))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should verify signature",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloElfFileWithSignature)).To(Succeed())
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify signature because wrong signature",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloElfFileWithOutdatedSignature)).To(HaveOccurred())
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify signature because no signature",
		func(ctx SpecContext, errMatcher types.GomegaMatcher) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloElfFile)).To(errMatcher)
		},
		Entry(
			"with x509 certs",
			MatchError(elf.ErrNoSignatureSection),
		),
	)

	DescribeTable("should fail to sign sectionless elf",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldElfBinary := readFile(helloSectionlessElfFile)
			newElfFilePath, cleanupTmpFile := makeTempFileCopy(helloSectionlessElfFile)
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newElfFilePath)).To(MatchError(elf.ErrNoSections))

			newElfBinary := readFile(newElfFilePath)
			Expect(newElfBinary).To(Equal(oldElfBinary))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify sectionless elf",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloSectionlessElfFile)).To(MatchError(elf.ErrNoSections))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify non-elf file",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloTxtFile)).To(Equal(elf.ErrNotELF))
		},
		Entry(
			"with x509 certs",
		),
	)
})
