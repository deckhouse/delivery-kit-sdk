package inhouse_test

import (
	"bytes"
	"debug/elf"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF byte signing", func() {
	g.It("signs and verifies new and replaced signatures through both APIs", func(ctx g.SpecContext) {
		original := readFile(helloElfFile)
		signed, err := inhouse.SignBytes(ctx, newSignerVerifier(ctx), original)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())

		resigned, err := inhouse.SignBytes(ctx, newSignerVerifier(ctx), signed)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, resigned)).To(m.Succeed())

		path := writeELF(resigned)
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, readFile(helloElfFileWithSignature))).To(m.Succeed())
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
