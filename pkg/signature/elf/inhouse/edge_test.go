package inhouse_test

import (
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

var _ = g.Describe("ELF signing boundaries", func() {
	g.DescribeTable("Given a legacy host-order digest, then verification is independent of the current host",
		func(ctx g.SpecContext, digest string, elfOrder, noteOrder binary.ByteOrder) {
			sv := newSignerVerifier(ctx)
			bundle, err := signature.Sign(ctx, sv, digest)
			m.Expect(err).NotTo(m.HaveOccurred())
			payload, err := json.Marshal(bundle)
			m.Expect(err).NotTo(m.HaveOccurred())
			note := make([]byte, 36+(len(payload)+3)&^3)
			noteOrder.PutUint32(note[:4], 23)
			noteOrder.PutUint32(note[4:8], uint32(len(payload)))
			noteOrder.PutUint32(note[8:12], 0x31415926)
			copy(note[12:], "delivery-kit.signature\x00")
			copy(note[36:], payload)
			data, err := elfedit.SetSection(ctx, minimalELF(elf.ELFCLASS64, elfOrder, elf.EM_X86_64), ".note.delivery-kit.signature", note, elfedit.SectionOptions{Type: elf.SHT_NOTE, Alignment: 4})
			m.Expect(err).NotTo(m.HaveOccurred())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, writeELF(data))).To(m.Succeed())
		},
		g.Entry("little-endian host", "080a38b4ca530cb1459476644616c285ca03817f6d6f210fd6d454c601fade81", binary.LittleEndian, binary.LittleEndian),
		g.Entry("big-endian host", "0d367a50600be384c9c58e34fa7083040f69690de359819e1022aa34a5f356e1", binary.LittleEndian, binary.LittleEndian),
		g.Entry("legacy LE note inside BE ELF", "080a38b4ca530cb1459476644616c285ca03817f6d6f210fd6d454c601fade81", binary.BigEndian, binary.LittleEndian),
		g.Entry("legacy BE note inside LE ELF", "0d367a50600be384c9c58e34fa7083040f69690de359819e1022aa34a5f356e1", binary.LittleEndian, binary.BigEndian),
	)

	g.It("Given a valid legacy signature with malformed section zero, then verification rejects it", func(ctx g.SpecContext) {
		data := readFile(helloElfFileWithSignature)
		path := writeELF(data)
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		shoff := binary.LittleEndian.Uint64(data[40:48])
		binary.LittleEndian.PutUint32(data[shoff+4:shoff+8], uint32(elf.SHT_PROGBITS))
		m.Expect(os.WriteFile(path, data, 0o700)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError("invalid section zero"))
	})

	g.It("Given a file-backed oversized name table, then the metadata budget rejects it before allocation", func(ctx g.SpecContext) {
		data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		binary.LittleEndian.PutUint64(data[672:680], 65<<20)
		path := writeELF(data)
		m.Expect(os.Truncate(path, (65<<20)+320)).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.MatchError(m.ContainSubstring("oversized section name table")))
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError(m.ContainSubstring("oversized section name table")))
		assertNoTempFiles(path)
	})

	g.It("Given a file-backed oversized section table, then the metadata budget rejects it before allocation", func(ctx g.SpecContext) {
		data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		binary.LittleEndian.PutUint16(data[60:62], 0)
		binary.LittleEndian.PutUint64(data[544:552], (64<<20)/64+1)
		path := writeELF(data)
		m.Expect(os.Truncate(path, 512+(64<<20)+64)).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.MatchError(m.ContainSubstring("metadata limit")))
		assertNoTempFiles(path)
	})

	g.It("Given a replacement by another writer, then finalization must not overwrite it", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		sv := newSignerVerifier(ctx)
		sv.SignerVerifier = &hookSigner{SignerVerifier: sv.SignerVerifier, after: func() {
			m.Expect(os.Rename(path, path+".old")).To(m.Succeed())
			m.Expect(os.WriteFile(path, []byte("concurrent replacement"), 0o600)).To(m.Succeed())
		}}
		m.Expect(inhouse.Sign(ctx, sv, path)).To(m.MatchError(m.ContainSubstring("changed during signing")))
		m.Expect(readFile(path)).To(m.Equal([]byte("concurrent replacement")))
		assertNoTempFiles(path)
	})

	g.It("Given an in-place change by another writer, then the post-write digest prevents finalization", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		sv := newSignerVerifier(ctx)
		data := readFile(path)
		text := parseTestELF(data).Section(".text")
		data[text.Offset] ^= 1
		sv.SignerVerifier = &hookSigner{SignerVerifier: sv.SignerVerifier, after: func() {
			m.Expect(os.WriteFile(path, data, 0o700)).To(m.Succeed())
		}}
		m.Expect(inhouse.Sign(ctx, sv, path)).To(m.MatchError(m.ContainSubstring("changed ELF digest")))
		m.Expect(readFile(path)).To(m.Equal(data))
		assertNoTempFiles(path)
	})

	g.It("Given a 600 MiB artifact, then signing streams it and verification succeeds", g.Label("e2e", "elf-large"), func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		m.Expect(os.Truncate(path, 600<<20)).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		info, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(info.Size()).To(m.BeNumerically(">", 600<<20))
		m.Expect(info.Size()).To(m.BeNumerically("<", 601<<20))
	})
})
