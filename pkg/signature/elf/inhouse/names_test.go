package inhouse_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"

	"github.com/deckhouse/elfedit"
	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("preserved ELF string tables", func() {
	g.It("Given fixed legacy digest vectors, the independent oracle retains both host orders", func() {
		plain := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		m.Expect(referenceELFDigest(plain, binary.LittleEndian)).To(m.Equal("080a38b4ca530cb1459476644616c285ca03817f6d6f210fd6d454c601fade81"))
		m.Expect(referenceELFDigest(plain, binary.BigEndian)).To(m.Equal("0d367a50600be384c9c58e34fa7083040f69690de359819e1022aa34a5f356e1"))
		shared := stringTableELF(elf.ELFCLASS64, binary.LittleEndian, true)
		m.Expect(referenceELFDigest(shared, binary.LittleEndian)).To(m.Equal("07cd1ad9ce4decfdb062fa82d01eaa92892fd4bdf71989c0728f401f218fdc7a"))
		m.Expect(referenceELFDigest(shared, binary.BigEndian)).To(m.Equal("43b4a88863867e18d632f8e8b4d7e34d8cba4edb869f64c67dfcc3dc96df3d8f"))
	})

	g.It("Given a detached table crossing the reserved index boundary, both APIs resolve extended numbering", func(ctx g.SpecContext) {
		data := stringTableELF(elf.ELFCLASS64, binary.LittleEndian, true)
		const count = int(elf.SHN_LORESERVE) - 1
		table := make([]byte, count*64)
		copy(table, data[512:512+4*64])
		binary.LittleEndian.PutUint64(data[40:48], uint64(len(data)))
		binary.LittleEndian.PutUint16(data[60:62], uint16(count))
		data = append(data, table...)
		sv := newSignerVerifier(ctx)
		for _, fileAPI := range []bool{false, true} {
			path := writeELF(data)
			var signed []byte
			if fileAPI {
				m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
				signed = readFile(path)
			} else {
				var err error
				signed, err = inhouse.SignBytes(ctx, sv, data)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(os.WriteFile(path, signed, 0o700)).To(m.Succeed())
			}
			m.Expect(binary.LittleEndian.Uint16(signed[60:62])).To(m.BeZero())
			m.Expect(binary.LittleEndian.Uint16(signed[62:64])).To(m.Equal(uint16(elf.SHN_XINDEX)))
			zero := testSectionHeader(signed, 0)
			m.Expect(zero.Size).To(m.Equal(uint64(count + 2)))
			m.Expect(zero.Link).To(m.Equal(uint32(count + 1)))
			m.Expect(testSectionHeader(signed, 2)).To(m.Equal(testSectionHeader(data, 2)))
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
			again, err := inhouse.SignBytes(ctx, sv, signed)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(again).To(m.Equal(signed))
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			m.Expect(readFile(path)).To(m.Equal(signed))
		}
	})

	g.It("Given an existing stale note on a noncanonical table, replacing it does not detach names", func(ctx g.SpecContext) {
		data, err := elfedit.SetSection(ctx, stringTableELF(elf.ELFCLASS64, binary.LittleEndian, true), ".note.delivery-kit.signature", nil, elfedit.SectionOptions{Type: elf.SHT_NOTE, Alignment: 4})
		m.Expect(err).NotTo(m.HaveOccurred())
		sv := newSignerVerifier(ctx)
		path := writeELF(data)
		m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
		fromBytes, err := inhouse.SignBytes(ctx, sv, data)
		m.Expect(err).NotTo(m.HaveOccurred())
		for _, signed := range [][]byte{readFile(path), fromBytes} {
			m.Expect(parseTestELF(signed).Sections).To(m.HaveLen(len(parseTestELF(data).Sections)))
			m.Expect(testSectionHeader(signed, 2)).To(m.Equal(testSectionHeader(data, 2)))
			m.Expect(referenceELFDigest(signed, binary.NativeEndian)).To(m.Equal(referenceELFDigest(data, binary.NativeEndian)))
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			again, err := inhouse.SignBytes(ctx, sv, signed)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(again).To(m.Equal(signed))
		}
	})

	g.DescribeTable("Given a noncanonical name table, both APIs preserve the source digest and symbol references",
		func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
			for _, shared := range []bool{false, true} {
				original := stringTableELF(class, order, shared)
				for _, fileAPI := range []bool{false, true} {
					sv := newSignerVerifier(ctx)
					calls := 0
					sv.SignerVerifier = &hookSigner{SignerVerifier: sv.SignerVerifier, after: func() { calls++ }}
					path := writeELF(original)
					var signed []byte
					if fileAPI {
						m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
						signed = readFile(path)
					} else {
						var err error
						signed, err = inhouse.SignBytes(ctx, sv, original)
						m.Expect(err).NotTo(m.HaveOccurred())
						m.Expect(os.WriteFile(path, signed, 0o700)).To(m.Succeed())
					}
					m.Expect(original).To(m.Equal(stringTableELF(class, order, shared)))
					assertStringTablePreserved(original, signed)
					m.Expect(parseTestELF(signed).Sections).To(m.HaveLen(len(parseTestELF(original).Sections) + 2))
					m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
					m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
					digest := referenceELFDigest(original, binary.NativeEndian)
					m.Expect(referenceELFDigest(signed, binary.NativeEndian)).To(m.Equal(digest))
					m.Expect(referenceELFDigest(signed, binary.BigEndian)).To(m.Equal(referenceELFDigest(original, binary.BigEndian)))
					note, err := parseTestELF(signed).Section(".note.delivery-kit.signature").Data()
					m.Expect(err).NotTo(m.HaveOccurred())
					var bundle signature.Bundle
					m.Expect(json.Unmarshal(note[36:36+order.Uint32(note[4:8])], &bundle)).To(m.Succeed())
					m.Expect(signature.VerifyBundle(ctx, bundle, digest, []string{cert_utils.RootCABase64})).To(m.Succeed())
					before, err := os.Stat(path)
					m.Expect(err).NotTo(m.HaveOccurred())
					m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
					after, err := os.Stat(path)
					m.Expect(err).NotTo(m.HaveOccurred())
					m.Expect(os.SameFile(before, after)).To(m.BeTrue())
					m.Expect(after.ModTime()).To(m.Equal(before.ModTime()))
					again, err := inhouse.SignBytes(ctx, sv, signed)
					m.Expect(err).NotTo(m.HaveOccurred())
					m.Expect(again).To(m.Equal(signed))
					m.Expect(readFile(path)).To(m.Equal(signed))
					m.Expect(calls).To(m.Equal(1))
					for _, name := range []string{".strtab", ".text", ".symtab"} {
						section := parseTestELF(signed).Section(name)
						if section == nil {
							continue
						}
						mutated := bytes.Clone(signed)
						offset := section.Offset
						if name == ".strtab" {
							offset += 33
						}
						mutated[offset] ^= 1
						m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, mutated)).To(m.MatchError(m.ContainSubstring("signature verification")))
					}
					sv.Chain = append(bytes.Clone(sv.Chain), '\n')
					replaced, err := inhouse.SignBytes(ctx, sv, signed)
					m.Expect(err).NotTo(m.HaveOccurred())
					m.Expect(replaced).NotTo(m.Equal(signed))
					m.Expect(parseTestELF(replaced).Sections).To(m.HaveLen(len(parseTestELF(signed).Sections)))
					m.Expect(referenceELFDigest(replaced, binary.NativeEndian)).To(m.Equal(digest))
					m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, replaced)).To(m.Succeed())
					m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
					m.Expect(parseTestELF(readFile(path)).Sections).To(m.HaveLen(len(parseTestELF(signed).Sections)))
					m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
				}
			}
		},
		g.Entry("ELF32 LE", elf.ELFCLASS32, binary.LittleEndian),
		g.Entry("ELF32 BE", elf.ELFCLASS32, binary.BigEndian),
		g.Entry("ELF64 LE", elf.ELFCLASS64, binary.LittleEndian),
		g.Entry("ELF64 BE", elf.ELFCLASS64, binary.BigEndian),
	)

	g.DescribeTable("Given a special table layout, SDK detaches only noncanonical names",
		func(ctx g.SpecContext, layout string) {
			data := stringTableELF(elf.ELFCLASS64, binary.LittleEndian, true)
			s := testSectionHeader(data, 2)
			switch layout {
			case "canonical":
				s.Name = 7
			case "allocated":
				s.Flags = uint64(elf.SHF_ALLOC)
			case "mapped":
				binary.LittleEndian.PutUint64(data[96:104], s.Off+s.Size)
			}
			putTestSection(data, 2, s)
			if layout == "collision" {
				var err error
				data, err = elfedit.SetSection(ctx, data, ".shstrtab", []byte("user"), elfedit.SectionOptions{})
				m.Expect(err).NotTo(m.HaveOccurred())
			}
			for _, fileAPI := range []bool{false, true} {
				path := writeELF(data)
				var signed []byte
				if fileAPI {
					m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
					signed = readFile(path)
				} else {
					var err error
					signed, err = inhouse.SignBytes(ctx, newSignerVerifier(ctx), data)
					m.Expect(err).NotTo(m.HaveOccurred())
				}
				added := 2
				if layout == "canonical" {
					added = 1
				} else {
					assertStringTablePreserved(data, signed)
				}
				m.Expect(parseTestELF(signed).Sections).To(m.HaveLen(len(parseTestELF(data).Sections) + added))
				m.Expect(referenceELFDigest(signed, binary.NativeEndian)).To(m.Equal(referenceELFDigest(data, binary.NativeEndian)))
				m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			}
		},
		g.Entry("canonical shared", "canonical"), g.Entry("allocated", "allocated"), g.Entry("mapped", "mapped"), g.Entry("collision", "collision"),
	)

	g.It("Given names at the metadata limit, enlarged output is rejected atomically", func(ctx g.SpecContext) {
		data := stringTableELF(elf.ELFCLASS64, binary.LittleEndian, true)
		s := testSectionHeader(data, 2)
		names := bytes.Clone(data[s.Off : s.Off+s.Size])
		s.Off, s.Size = uint64(len(data)), (64<<20)-4*64
		data = append(data, make([]byte, int(s.Size))...)
		copy(data[s.Off:], names)
		putTestSection(data, 2, s)
		path := writeELF(data)
		before, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		sv := newSignerVerifier(ctx)
		m.Expect(inhouse.Sign(ctx, sv, path)).To(m.MatchError(m.ContainSubstring("read signed ELF: invalid or oversized section name table")))
		after, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(os.SameFile(before, after)).To(m.BeTrue())
		m.Expect(readFile(path)).To(m.Equal(data))
		assertNoTempFiles(path)
		pristine := bytes.Clone(data)
		out, err := inhouse.SignBytes(ctx, sv, data)
		m.Expect(err).To(m.MatchError(m.ContainSubstring("read signed ELF: invalid or oversized section name table")))
		m.Expect(out).To(m.BeNil())
		m.Expect(data).To(m.Equal(pristine))
	})

	g.It("Given canceled or malformed shared names, neither API modifies the source", func(ctx g.SpecContext) {
		data := stringTableELF(elf.ELFCLASS64, binary.LittleEndian, true)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		sv := newSignerVerifier(ctx)
		for _, malformed := range []bool{false, true} {
			callCtx := canceled
			if malformed {
				callCtx = ctx
				s := testSectionHeader(data, 2)
				data[s.Off+s.Size-1] = 'x'
			}
			path := writeELF(data)
			pristine := bytes.Clone(data)
			m.Expect(inhouse.Sign(callCtx, sv, path)).To(m.HaveOccurred())
			out, err := inhouse.SignBytes(callCtx, sv, data)
			m.Expect(err).To(m.HaveOccurred())
			m.Expect(out).To(m.BeNil())
			m.Expect(data).To(m.Equal(pristine))
			m.Expect(readFile(path)).To(m.Equal(data))
			assertNoTempFiles(path)
		}
	})
})
