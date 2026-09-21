package inhouse_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF byte signing", func() {
	g.It("signs and verifies new and replaced signatures through both APIs", func(ctx g.SpecContext) {
		original := readFile(helloElfFile)
		signerVerifier := newSignerVerifier(ctx)
		signCalls := 0
		signerVerifier.SignerVerifier = &hookSigner{SignerVerifier: signerVerifier.SignerVerifier, after: func() { signCalls++ }}
		signed, err := inhouse.SignBytes(ctx, signerVerifier, original)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())

		resigned, err := inhouse.SignBytes(ctx, signerVerifier, signed)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, resigned)).To(m.Succeed())
		m.Expect(resigned).To(m.Equal(signed))
		m.Expect(signCalls).To(m.Equal(1))

		path := writeELF(resigned)
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, readFile(helloElfFileWithSignature))).To(m.Succeed())
	})

	g.It("re-signs when the certificate or chain changes", func(ctx g.SpecContext) {
		signerVerifier := newSignerVerifier(ctx)
		signed, err := inhouse.SignBytes(ctx, signerVerifier, readFile(helloElfFile))
		m.Expect(err).NotTo(m.HaveOccurred())

		changedCert := &signver.SignerVerifier{
			SignerVerifier: signerVerifier.SignerVerifier,
			Cert:           append(bytes.Clone(signerVerifier.Cert), '\n'),
			Chain:          bytes.Clone(signerVerifier.Chain),
		}
		resigned, err := inhouse.SignBytes(ctx, changedCert, signed)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(resigned).NotTo(m.Equal(signed))

		changedChain := &signver.SignerVerifier{
			SignerVerifier: signerVerifier.SignerVerifier,
			Cert:           bytes.Clone(changedCert.Cert),
			Chain:          append(bytes.Clone(changedCert.Chain), '\n'),
		}
		resignedAgain, err := inhouse.SignBytes(ctx, changedChain, resigned)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(resignedAgain).NotTo(m.Equal(resigned))
	})

	g.It("rewrites a valid legacy note that uses host byte order", func(ctx g.SpecContext) {
		signerVerifier := newSignerVerifier(ctx)
		signed, err := inhouse.SignBytes(ctx, signerVerifier, minimalELF(elf.ELFCLASS64, binary.BigEndian, elf.EM_AARCH64))
		m.Expect(err).NotTo(m.HaveOccurred())

		legacy := bytes.Clone(signed)
		file, err := elf.NewFile(bytes.NewReader(legacy))
		m.Expect(err).NotTo(m.HaveOccurred())
		section := file.Section(".note.delivery-kit.signature")
		m.Expect(section).NotTo(m.BeNil())
		note := legacy[section.Offset : section.Offset+section.Size]
		nameSize := binary.BigEndian.Uint32(note[:4])
		payloadSize := binary.BigEndian.Uint32(note[4:8])
		noteType := binary.BigEndian.Uint32(note[8:12])
		binary.LittleEndian.PutUint32(note[:4], nameSize)
		binary.LittleEndian.PutUint32(note[4:8], payloadSize)
		binary.LittleEndian.PutUint32(note[8:12], noteType)
		m.Expect(file.Close()).To(m.Succeed())

		resigned, err := inhouse.SignBytes(ctx, signerVerifier, legacy)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(resigned).NotTo(m.Equal(legacy))
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, resigned)).To(m.Succeed())
	})

	g.It("rejects malformed ELF and an invalid signature", func(ctx g.SpecContext) {
		malformed := bytes.Clone(readFile(helloElfFile))
		malformed[4] = 0
		_, err := inhouse.SignBytes(ctx, newSignerVerifier(ctx), malformed)
		m.Expect(err).To(m.HaveOccurred())

		signed, err := inhouse.SignBytes(ctx, newSignerVerifier(ctx), readFile(helloElfFile))
		m.Expect(err).NotTo(m.HaveOccurred())
		f, err := elf.NewFile(bytes.NewReader(signed))
		m.Expect(err).NotTo(m.HaveOccurred())
		section := f.Section(".text")
		m.Expect(section).NotTo(m.BeNil())
		signed[section.Offset] ^= 1
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.MatchError(m.ContainSubstring("signature verification")))
	})
})
