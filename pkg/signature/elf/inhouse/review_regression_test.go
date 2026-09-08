package inhouse_test

import (
	"debug/elf"
	"encoding/binary"
	"os"

	"github.com/deckhouse/elfedit"
	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF review regressions", func() {
	g.It("Given a bsign section, then changing its payload does not invalidate the SDK signature", func(ctx g.SpecContext) {
		data, err := elfedit.SetSection(ctx, minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64), "signature", []byte("bsign payload"), elfedit.SectionOptions{})
		m.Expect(err).NotTo(m.HaveOccurred())
		path := writeELF(data)
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		data = readFile(path)
		section := parseTestELF(data).Section("signature")
		data[section.Offset] ^= 1
		m.Expect(os.WriteFile(path, data, 0o700)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
	})

	g.DescribeTable("Given a section name sharing an excluded prefix, then its payload remains authenticated", func(ctx g.SpecContext, name string) {
		data, err := elfedit.SetSection(ctx, minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64), name, []byte("authenticated payload"), elfedit.SectionOptions{})
		m.Expect(err).NotTo(m.HaveOccurred())
		path := writeELF(data)
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		data = readFile(path)
		section := parseTestELF(data).Section(name)
		data[section.Offset] ^= 1
		m.Expect(os.WriteFile(path, data, 0o700)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).NotTo(m.Succeed())
	},
		g.Entry("bsign prefix", "signature2"),
		g.Entry("name table prefix", ".shstrtab.dwo"),
		g.Entry("SDK note prefix", ".note.delivery-kit.signatureX"),
	)

	g.It("Given an unterminated name table, then both entry points reject it without panicking", func(ctx g.SpecContext) {
		data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		section := parseTestELF(data).Section(".shstrtab")
		data[section.Offset+section.FileSize-1] = 'x'
		path := writeELF(data)
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.MatchError("unterminated section name table"))
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError("unterminated section name table"))
		m.Expect(readFile(path)).To(m.Equal(data))
	})

	g.It("Given duplicate valid signature notes, then verification rejects the ambiguity", func(ctx g.SpecContext) {
		path := writeELF(minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64))
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		data := readFile(path)
		f := parseTestELF(data)
		section := f.Section(".note.delivery-kit.signature")
		note := data[section.Offset : section.Offset+section.FileSize]
		duplicate, err := elfedit.SetSection(ctx, data, ".duplicate", note, elfedit.SectionOptions{Type: elf.SHT_NOTE})
		m.Expect(err).NotTo(m.HaveOccurred())
		updated := parseTestELF(duplicate)
		shoff := binary.LittleEndian.Uint64(duplicate[40:48])
		for i, s := range updated.Sections {
			if s.Name == ".note.delivery-kit.signature" {
				copy(duplicate[shoff+uint64(len(updated.Sections)-1)*64:][:4], duplicate[shoff+uint64(i)*64:][:4])
			}
		}
		m.Expect(os.WriteFile(path, duplicate, 0o700)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError("duplicate signature section"))
	})

	g.It("Given a section range beyond EOF, then metadata validation rejects it", func(ctx g.SpecContext) {
		data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		binary.LittleEndian.PutUint64(data[600:608], uint64(len(data)-2))
		path := writeELF(data)
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError("section 1 outside file"))
	})

	g.It("Given a directory, then both entry points reject it as non-regular", func(ctx g.SpecContext) {
		path := g.GinkgoT().TempDir()
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.MatchError("ELF requires a regular file"))
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError("ELF requires a regular file"))
	})
})
