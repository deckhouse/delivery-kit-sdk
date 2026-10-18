package inhouse_test

import (
	"debug/elf"
	"os"
	"path/filepath"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF signature note groups", func() {
	g.DescribeTable("Given compiler-generated grouped and ungrouped notes, when signing, then both APIs retain only structural membership and remain idempotent",
		func(ctx g.SpecContext, target string, class elf.Class, order elf.Data) {
			for _, kind := range []string{"plain", "group"} {
				input, err := os.ReadFile(filepath.Join("testdata", "spec", "note-"+kind+"-"+target+".elf"))
				m.Expect(err).NotTo(m.HaveOccurred())
				original := parseTestELF(input)
				m.Expect(original.Type).To(m.Equal(elf.ET_REL))
				m.Expect(original.Class).To(m.Equal(class))
				m.Expect(original.Data).To(m.Equal(order))
				note := original.Section(".note.delivery-kit.signature")
				m.Expect(note).NotTo(m.BeNil())
				symbols, err := original.Symbols()
				m.Expect(err).NotTo(m.HaveOccurred())
				symbolIndex := uint32(0)
				for i, symbol := range symbols {
					if symbol.Name == "spec_group" {
						m.Expect(symbol.Section).To(m.Equal(elf.SHN_ABS))
						symbolIndex = uint32(i + 1)
					}
				}
				m.Expect(symbolIndex).NotTo(m.BeZero())

				wantFlags := elf.SectionFlag(0)
				var members []byte
				group := original.Section(".group")
				if kind == "group" {
					wantFlags = elf.SHF_GROUP
					m.Expect(group).NotTo(m.BeNil())
					m.Expect(group.Entsize).To(m.Equal(uint64(4)))
					m.Expect(group.Info).To(m.Equal(symbolIndex))
					m.Expect(original.Sections[group.Link].Type).To(m.Equal(elf.SHT_SYMTAB))
					members, err = group.Data()
					m.Expect(err).NotTo(m.HaveOccurred())
					m.Expect(members).To(m.HaveLen(8))
					m.Expect(original.ByteOrder.Uint32(members)).To(m.Equal(uint32(1)))
					index := original.ByteOrder.Uint32(members[4:8])
					m.Expect(original.Sections[index]).To(m.BeIdenticalTo(note))
					for i, s := range original.Sections {
						if s == group {
							m.Expect(uint32(i)).To(m.BeNumerically("<", index))
						}
					}
				} else {
					m.Expect(group).To(m.BeNil())
				}
				m.Expect(note.Flags).To(m.Equal(wantFlags | elf.SHF_WRITE))
				sv := newSignerVerifier(ctx)
				signCalls := 0
				sv.SignerVerifier = &hookSigner{SignerVerifier: sv.SignerVerifier, after: func() { signCalls++ }}
				fromBytes, err := inhouse.SignBytes(ctx, sv, input)
				m.Expect(err).NotTo(m.HaveOccurred())
				path := writeELF(input)
				m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
				fromFile := readFile(path)
				m.Expect(fromFile).To(m.Equal(fromBytes))
				m.Expect(signCalls).To(m.Equal(2))
				for _, signed := range [][]byte{fromBytes, fromFile} {
					edited := parseTestELF(signed)
					m.Expect(edited.Sections).To(m.HaveLen(len(original.Sections)))
					m.Expect(edited.Section(".note.delivery-kit.signature").Flags).To(m.Equal(wantFlags))
					for i, s := range original.Sections {
						if s != note {
							m.Expect(edited.Sections[i].SectionHeader).To(m.Equal(s.SectionHeader))
						}
					}
					if group != nil {
						afterMembers, err := edited.Section(".group").Data()
						m.Expect(err).NotTo(m.HaveOccurred())
						m.Expect(afterMembers).To(m.Equal(members))
						index := original.ByteOrder.Uint32(afterMembers[4:8])
						m.Expect(edited.Sections[index].Flags & elf.SHF_GROUP).To(m.Equal(elf.SHF_GROUP))
					}
					m.Expect(referenceELFDigest(signed, original.ByteOrder)).To(m.Equal(referenceELFDigest(input, original.ByteOrder)))
					m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
				}
				m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
				again, err := inhouse.SignBytes(ctx, sv, fromBytes)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(again).To(m.Equal(fromBytes))
				before, err := os.Stat(path)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
				after, err := os.Stat(path)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(os.SameFile(before, after)).To(m.BeTrue())
				m.Expect(readFile(path)).To(m.Equal(fromFile))
				m.Expect(signCalls).To(m.Equal(2))
				assertNoTempFiles(path)
			}
		}, g.Entry("ELF32 LE", "i386-linux-gnu", elf.ELFCLASS32, elf.ELFDATA2LSB), g.Entry("ELF32 BE", "armeb-linux-gnueabi", elf.ELFCLASS32, elf.ELFDATA2MSB), g.Entry("ELF64 LE", "x86_64-linux-gnu", elf.ELFCLASS64, elf.ELFDATA2LSB), g.Entry("ELF64 BE", "aarch64_be-linux-gnu", elf.ELFCLASS64, elf.ELFDATA2MSB))
})
