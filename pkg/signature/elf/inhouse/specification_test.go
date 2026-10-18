package inhouse_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF specification fixtures", func() {
	g.It("Given canonical PN_XNUM boundaries, when signing, then raw legacy count hashing and resolved metadata are preserved", func(ctx g.SpecContext) {
		for _, count := range []uint32{0xffff, 0x10000} {
			data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
			first := bytes.Clone(data[64:120])
			phoff := len(data)
			data = append(data, make([]byte, int(count)*56)...)
			copy(data[phoff:], first)
			binary.LittleEndian.PutUint64(data[32:40], uint64(phoff))
			binary.LittleEndian.PutUint16(data[56:58], 0xffff)
			putTestSection(data, 0, elf.Section64{Info: count})
			binary.LittleEndian.PutUint32(data[phoff+int(count-1)*56+4:], uint32(elf.PF_R))
			h := sha256.New()
			for i := uint32(0); i < 0xffff; i++ {
				p := elf.Prog64{}
				if i == 0 {
					p.Type = uint32(elf.PT_LOAD)
					p.Flags = uint32(elf.PF_R | elf.PF_X)
				} else if i == count-1 {
					p.Flags = uint32(elf.PF_R)
				}
				m.Expect(binary.Write(h, binary.NativeEndian, p)).To(m.Succeed())
			}
			text := testSectionHeader(data, 1)
			m.Expect(binary.Write(h, binary.NativeEndian, elf.Section64{Name: text.Name, Type: text.Type, Flags: text.Flags})).To(m.Succeed())
			_, err := h.Write(data[text.Off : text.Off+text.Size])
			m.Expect(err).NotTo(m.HaveOccurred())
			digest := fmt.Sprintf("%x", h.Sum(nil))
			sv := newSignerVerifier(ctx)
			signed, err := inhouse.SignBytes(ctx, sv, data)
			m.Expect(err).NotTo(m.HaveOccurred())
			path := writeELF(data)
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			m.Expect(readFile(path)).To(m.Equal(signed))
			m.Expect(binary.LittleEndian.Uint16(signed[56:58])).To(m.Equal(uint16(0xffff)))
			m.Expect(testSectionHeader(signed, 0).Info).To(m.Equal(count))
			m.Expect(signed[phoff : phoff+int(count)*56]).To(m.Equal(data[phoff:]))
			assertBundleDigest(ctx, signed, 3, digest)
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		}
	})

	g.DescribeTable("Given zero-size, NOBITS and opaque compressed sections, when signing, then both APIs preserve their headers and raw contents", func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
		for _, kind := range []string{"empty", "nobits", "compressed"} {
			input := minimalELF(class, order, elf.EM_ARM)
			if class == elf.ELFCLASS64 {
				input = minimalELF(class, order, elf.EM_AARCH64)
			}
			sectionSize := 64
			if class == elf.ELFCLASS32 {
				sectionSize = 40
				order.PutUint16(input[48:50], 4)
			} else {
				order.PutUint16(input[60:62], 4)
			}
			input = append(input, make([]byte, sectionSize)...)
			s := elf.Section64{Type: uint32(elf.SHT_PROGBITS), Off: uint64(len(input)), Addralign: 1}
			var raw []byte
			if kind == "nobits" {
				s.Type = uint32(elf.SHT_NOBITS)
				s.Flags = uint64(elf.SHF_ALLOC | elf.SHF_WRITE)
				s.Off = 260
				s.Addr = 0x400104
				s.Size = 128
				s.Addralign = 4
				if class == elf.ELFCLASS32 {
					order.PutUint32(input[72:76], 388)
				} else {
					order.PutUint64(input[104:112], 388)
				}
			} else if kind == "compressed" {
				var encoded bytes.Buffer
				payload := []byte("opaque compressed section fixture")
				var header any = elf.Chdr64{Type: uint32(elf.COMPRESS_ZLIB), Size: uint64(len(payload)), Addralign: 1}
				s.Addralign = 8
				if class == elf.ELFCLASS32 {
					header = elf.Chdr32{Type: uint32(elf.COMPRESS_ZLIB), Size: uint32(len(payload)), Addralign: 1}
					s.Addralign = 4
				}
				m.Expect(binary.Write(&encoded, order, header)).To(m.Succeed())
				z := zlib.NewWriter(&encoded)
				_, err := z.Write(payload)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(z.Close()).To(m.Succeed())
				raw = encoded.Bytes()
				s.Flags = uint64(elf.SHF_COMPRESSED)
				s.Size = uint64(len(raw))
				input = append(input, raw...)
			}
			putTestSection(input, 3, s)
			digest := referenceELFDigest(input, binary.NativeEndian)
			sv := newSignerVerifier(ctx)
			signed, err := inhouse.SignBytes(ctx, sv, input)
			m.Expect(err).NotTo(m.HaveOccurred())
			path := writeELF(input)
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
			m.Expect(readFile(path)).To(m.Equal(signed))
			m.Expect(testSectionHeader(signed, 3)).To(m.Equal(s))
			m.Expect(parseTestELF(signed).Section(".note.delivery-kit.signature").Flags).To(m.BeZero())
			if kind == "compressed" {
				m.Expect(signed[s.Off : s.Off+s.Size]).To(m.Equal(raw))
				decoded, err := parseTestELF(signed).Sections[3].Data()
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(string(decoded)).To(m.Equal("opaque compressed section fixture"))
			}
			assertBundleDigest(ctx, signed, 4, digest)
			m.Expect(inhouse.VerifyBytes(ctx, []string{cert_utils.RootCABase64}, signed)).To(m.Succeed())
		}
	}, g.Entry("ELF32 LE", elf.ELFCLASS32, binary.LittleEndian), g.Entry("ELF32 BE", elf.ELFCLASS32, binary.BigEndian), g.Entry("ELF64 LE", elf.ELFCLASS64, binary.LittleEndian), g.Entry("ELF64 BE", elf.ELFCLASS64, binary.BigEndian))

	g.DescribeTable("Given unsupported selected name-table configurations, when signing, then exact errors leave both inputs unchanged", func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
		for _, compressed := range []bool{false, true} {
			data := minimalELF(class, order, elf.EM_ARM)
			if class == elf.ELFCLASS64 {
				data = minimalELF(class, order, elf.EM_AARCH64)
			}
			want := "invalid section name table index"
			if compressed {
				s := testSectionHeader(data, 2)
				names := bytes.Clone(data[s.Off : s.Off+s.Size])
				var encoded bytes.Buffer
				var header any = elf.Chdr64{Type: uint32(elf.COMPRESS_ZLIB), Size: s.Size, Addralign: 1}
				s.Addralign = 8
				if class == elf.ELFCLASS32 {
					header = elf.Chdr32{Type: uint32(elf.COMPRESS_ZLIB), Size: uint32(s.Size), Addralign: 1}
					s.Addralign = 4
				}
				m.Expect(binary.Write(&encoded, order, header)).To(m.Succeed())
				z := zlib.NewWriter(&encoded)
				_, err := z.Write(names)
				m.Expect(err).NotTo(m.HaveOccurred())
				m.Expect(z.Close()).To(m.Succeed())
				s.Flags = uint64(elf.SHF_COMPRESSED)
				s.Off = uint64(len(data))
				s.Size = uint64(encoded.Len())
				data = append(data, encoded.Bytes()...)
				putTestSection(data, 2, s)
				want = "invalid or oversized section name table"
			} else {
				for i := 1; i < 3; i++ {
					s := testSectionHeader(data, i)
					s.Name = 0
					putTestSection(data, i, s)
				}
				if class == elf.ELFCLASS32 {
					order.PutUint16(data[50:52], 0)
				} else {
					order.PutUint16(data[62:64], 0)
				}
			}
			pristine := bytes.Clone(data)
			path := writeELF(data)
			sv := newSignerVerifier(ctx)
			out, err := inhouse.SignBytes(ctx, sv, data)
			m.Expect(err).To(m.MatchError(want))
			m.Expect(out).To(m.BeNil())
			m.Expect(data).To(m.Equal(pristine))
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.MatchError(want))
			m.Expect(readFile(path)).To(m.Equal(pristine))
			assertNoTempFiles(path)
		}
	}, g.Entry("ELF32 LE", elf.ELFCLASS32, binary.LittleEndian), g.Entry("ELF32 BE", elf.ELFCLASS32, binary.BigEndian), g.Entry("ELF64 LE", elf.ELFCLASS64, binary.LittleEndian), g.Entry("ELF64 BE", elf.ELFCLASS64, binary.BigEndian))
})
