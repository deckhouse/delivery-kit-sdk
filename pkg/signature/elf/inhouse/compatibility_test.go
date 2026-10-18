package inhouse_test

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/deckhouse/elfedit"
	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF inactive metadata compatibility", func() {
	g.DescribeTable("Given unused program geometry, when signing, then both APIs preserve the original digest and are idempotent", func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
		sv := newSignerVerifier(ctx)
		digest := referenceELFDigest(unusedProgramELF(class, order, 256), binary.NativeEndian)
		for _, off := range []uint64{320, ^uint64(0)} {
			input := unusedProgramELF(class, order, off)
			pristine := bytes.Clone(input)
			for _, fileAPI := range []bool{false, true} {
				path := writeELF(input)
				var signed []byte
				if fileAPI {
					m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
					signed = readFile(path)
				} else {
					var err error
					signed, err = inhouse.SignBytes(ctx, sv, input)
					m.Expect(err).NotTo(m.HaveOccurred())
					m.Expect(os.WriteFile(path, signed, 0o700)).To(m.Succeed())
				}
				m.Expect(input).To(m.Equal(pristine))
				assertBundleDigest(ctx, signed, 3, digest)
				m.Expect(signed[64:176]).To(m.Equal(input[64:176]))
				m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
				m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
				again, err := inhouse.SignBytes(ctx, sv, signed)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(again).To(m.Equal(signed))
				before, err := os.Stat(path)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
				after, err := os.Stat(path)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(os.SameFile(before, after)).To(m.BeTrue())
				m.Expect(readFile(path)).To(m.Equal(signed))
			}
			bad := bytes.Clone(input)
			phoff := 120
			if class == elf.ELFCLASS32 {
				phoff = 84
			}
			order.PutUint32(bad[phoff:], uint32(elf.PT_LOAD))
			if off == 320 {
				continue
			}
			path := writeELF(bad)
			out, err := inhouse.SignBytes(ctx, sv, bad)
			m.Expect(err).To(m.MatchError("program segment outside file"))
			m.Expect(out).To(m.BeNil())
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.MatchError("program segment outside file"))
			m.Expect(readFile(path)).To(m.Equal(bad))
			assertNoTempFiles(path)
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, bad)).To(m.MatchError("program segment outside file"))
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError("program segment outside file"))
		}
	}, g.Entry("32 LE", elf.ELFCLASS32, binary.LittleEndian), g.Entry("32 BE", elf.ELFCLASS32, binary.BigEndian), g.Entry("64 LE", elf.ELFCLASS64, binary.LittleEndian), g.Entry("64 BE", elf.ELFCLASS64, binary.BigEndian))

	g.DescribeTable("Given inactive entries, when signed, then both legacy host orders and every inactive hash contribution remain covered", func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
		input := inactiveEntriesELF(class, order)
		m.Expect(referenceELFDigest(input, binary.LittleEndian)).To(m.Equal("a8177df92747940a2c67c27e0761054b1bd8f69711c54769732793dce8cc3483"))
		m.Expect(referenceELFDigest(input, binary.BigEndian)).To(m.Equal("a804a64fbdecf9022e4653475bb7305edab2a629466e0fd81f74750f75fc8a6f"))
		digest := referenceELFDigest(input, binary.NativeEndian)
		sv := newSignerVerifier(ctx)
		for _, hostOrder := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			bundle, err := signature.Sign(ctx, sv, referenceELFDigest(input, hostOrder))
			m.Expect(err).NotTo(m.HaveOccurred())
			payload, err := json.Marshal(bundle)
			m.Expect(err).NotTo(m.HaveOccurred())
			note := make([]byte, 36+(len(payload)+3)&^3)
			order.PutUint32(note[:4], 23)
			order.PutUint32(note[4:8], uint32(len(payload)))
			order.PutUint32(note[8:12], 0x31415926)
			copy(note[12:], "delivery-kit.signature\x00")
			copy(note[36:], payload)
			signed, err := elfedit.SetSection(ctx, input, ".note.delivery-kit.signature", note, elfedit.SectionOptions{Type: elf.SHT_NOTE, Alignment: 4})
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, writeELF(signed))).To(m.Succeed())
		}

		for _, fileAPI := range []bool{false, true} {
			path := writeELF(input)
			var signed []byte
			if fileAPI {
				m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
				signed = readFile(path)
			} else {
				var err error
				signed, err = inhouse.SignBytes(ctx, sv, input)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(os.WriteFile(path, signed, 0o700)).To(m.Succeed())
			}
			assertBundleDigest(ctx, signed, 4, digest)
			m.Expect(testSectionHeader(signed, 3)).To(m.Equal(testSectionHeader(input, 3)))
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
			again, err := inhouse.SignBytes(ctx, sv, signed)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(again).To(m.Equal(signed))
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			m.Expect(readFile(path)).To(m.Equal(signed))
			for _, kind := range []string{"inactive payload", "inactive header", "unused program flags"} {
				changed := bytes.Clone(signed)
				switch kind {
				case "inactive payload":
					changed[181] ^= 1
				case "inactive header":
					s := testSectionHeader(changed, 3)
					s.Flags = 0x4321
					putTestSection(changed, 3, s)
				case "unused program flags":
					off := 124
					if class == elf.ELFCLASS32 {
						off = 108
					}
					order.PutUint32(changed[off:], 6)
				}
				m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, changed)).NotTo(m.Succeed(), kind)
				m.Expect(os.WriteFile(path, changed, 0o700)).To(m.Succeed())
				m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).NotTo(m.Succeed(), kind)
			}
		}
	}, g.Entry("32 LE", elf.ELFCLASS32, binary.LittleEndian), g.Entry("32 BE", elf.ELFCLASS32, binary.BigEndian), g.Entry("64 LE", elf.ELFCLASS64, binary.LittleEndian), g.Entry("64 BE", elf.ELFCLASS64, binary.BigEndian))

	g.DescribeTable("Given an inactive signature alias before or after the note, when verifying or re-signing, then only the live note is selected", func(ctx g.SpecContext, before bool) {
		sv := newSignerVerifier(ctx)
		signed, err := inhouse.SignBytes(ctx, sv, minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64))
		m.Expect(err).NotTo(m.HaveOccurred())
		input, err := elfedit.SetSection(ctx, signed, ".unused", nil, elfedit.SectionOptions{})
		m.Expect(err).NotTo(m.HaveOccurred())
		note, alias := testSectionHeader(input, 3), testSectionHeader(input, 4)
		alias.Type, alias.Name = uint32(elf.SHT_NULL), note.Name
		index := 3
		if before {
			putTestSection(input, 3, alias)
			putTestSection(input, 4, note)
			index = 4
		} else {
			putTestSection(input, 4, alias)
		}
		digest := referenceELFDigest(input, binary.NativeEndian)
		m.Expect(digest).To(m.Equal(referenceELFDigest(signed, binary.NativeEndian)))
		assertBundleDigest(ctx, input, index, digest)
		path := writeELF(input)
		m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, input)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		again, err := inhouse.SignBytes(ctx, sv, input)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(again).To(m.Equal(input))
		m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
		m.Expect(readFile(path)).To(m.Equal(input))
	}, g.Entry("before", true), g.Entry("after", false))

	g.It("Given inactive fields outside legacy representability, when signing, then both APIs fail atomically", func(ctx g.SpecContext) {
		sv := newSignerVerifier(ctx)
		for _, kind := range []string{"name", "range"} {
			input := inactiveEntriesELF(elf.ELFCLASS64, binary.LittleEndian)
			s := testSectionHeader(input, 3)
			if kind == "name" {
				s.Name = ^uint32(0)
			} else {
				s.Off = ^uint64(0)
				s.Size = 1
			}
			putTestSection(input, 3, s)
			pristine := bytes.Clone(input)
			path := writeELF(input)
			output, err := inhouse.SignBytes(ctx, sv, input)
			m.Expect(err).To(m.HaveOccurred())
			m.Expect(output).To(m.BeNil())
			m.Expect(input).To(m.Equal(pristine))
			if kind == "name" {
				m.Expect(err).To(m.MatchError("section name outside table"))
			}
			m.Expect(inhouse.Sign(ctx, sv, path)).NotTo(m.Succeed())
			m.Expect(readFile(path)).To(m.Equal(pristine))
			assertNoTempFiles(path)
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, input)).NotTo(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).NotTo(m.Succeed())
		}
	})
})

var _ = g.Describe("ELF empty selected name table", func() {
	g.DescribeTable("Given an empty selected table, when signing, then original raw metadata and digest survive both APIs and repeat signing", func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
		input := minimalELF(class, order, elf.EM_X86_64)
		sections := []elf.Section64{{}, testSectionHeader(input, 1), testSectionHeader(input, 2)}
		for i := 1; i < 3; i++ {
			s := &sections[i]
			s.Name = 0
			if i == 2 {
				s.Size = 0
				s.Off = uint64(len(input))
			}
			putTestSection(input, i, *s)
		}
		h := sha256.New()
		m.Expect(binary.Write(h, binary.NativeEndian, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X)})).To(m.Succeed())
		for _, s := range sections[1:] {
			m.Expect(binary.Write(h, binary.NativeEndian, elf.Section64{Name: s.Name, Type: s.Type, Flags: s.Flags})).To(m.Succeed())
			_, err := h.Write(input[s.Off : s.Off+s.Size])
			m.Expect(err).NotTo(m.HaveOccurred())
		}
		digest := fmt.Sprintf("%x", h.Sum(nil))
		sv := newSignerVerifier(ctx)
		for _, fileAPI := range []bool{false, true} {
			path := writeELF(input)
			var signed []byte
			if fileAPI {
				m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
				signed = readFile(path)
			} else {
				var err error
				signed, err = inhouse.SignBytes(ctx, sv, input)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(os.WriteFile(path, signed, 0o700)).To(m.Succeed())
			}
			for i, s := range sections {
				m.Expect(testSectionHeader(signed, i)).To(m.Equal(s))
			}
			assertBundleDigest(ctx, signed, 3, digest)
			m.Expect(referenceELFDigest(signed, binary.NativeEndian)).To(m.Equal(digest))
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
			again, err := inhouse.SignBytes(ctx, sv, signed)
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(again).To(m.Equal(signed))
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			m.Expect(readFile(path)).To(m.Equal(signed))
		}
		invalid := bytes.Clone(input)
		s := sections[1]
		s.Name = 1
		putTestSection(invalid, 1, s)
		path := writeELF(invalid)
		output, err := inhouse.SignBytes(ctx, sv, invalid)
		m.Expect(err).To(m.HaveOccurred())
		m.Expect(output).To(m.BeNil())
		m.Expect(inhouse.Sign(ctx, sv, path)).NotTo(m.Succeed())
		m.Expect(readFile(path)).To(m.Equal(invalid))
		assertNoTempFiles(path)
	}, g.Entry("32 LE", elf.ELFCLASS32, binary.LittleEndian), g.Entry("32 BE", elf.ELFCLASS32, binary.BigEndian), g.Entry("64 LE", elf.ELFCLASS64, binary.LittleEndian), g.Entry("64 BE", elf.ELFCLASS64, binary.BigEndian))
})
