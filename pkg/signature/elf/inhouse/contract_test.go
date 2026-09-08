package inhouse_test

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

var _ = g.Describe("ELF signing contract", func() {
	g.DescribeTable("Given an ELF encoding, when signed twice, then both signatures verify and loaded bytes survive",
		func(ctx g.SpecContext, class elf.Class, order binary.ByteOrder) {
			for _, machine := range []elf.Machine{elf.EM_386, elf.EM_X86_64, elf.EM_ARM, elf.EM_AARCH64, elf.EM_PPC, elf.EM_PPC64, elf.EM_S390, elf.Machine(0xfffe)} {
				original := minimalELF(class, order, machine)
				path := writeELF(original)
				sv := newSignerVerifier(ctx)
				for range 2 {
					m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
					m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
					assertLoadPreserved(original, readFile(path))
					written := readFile(path)
					noteSection := parseTestELF(written).Section(".note.delivery-kit.signature")
					m.Expect(order.Uint32(written[noteSection.Offset+8 : noteSection.Offset+12])).To(m.Equal(uint32(0x31415926)))
				}
			}
		},
		g.Entry("ELF32 little-endian", elf.ELFCLASS32, binary.LittleEndian),
		g.Entry("ELF32 big-endian", elf.ELFCLASS32, binary.BigEndian),
		g.Entry("ELF64 little-endian", elf.ELFCLASS64, binary.LittleEndian),
		g.Entry("ELF64 big-endian", elf.ELFCLASS64, binary.BigEndian),
	)

	g.It("Given an executable, when signed, then it retains permissions and runs", func(ctx g.SpecContext) {
		if runtime.GOOS != "linux" {
			g.Skip("execution requires Linux")
		}
		original := readFile("/bin/true")
		path := writeELF(original)
		m.Expect(os.Chmod(path, 0o751)).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		info, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(info.Mode().Perm()).To(m.Equal(os.FileMode(0o751)))
		assertLoadPreserved(original, readFile(path))
		m.Expect(exec.CommandContext(ctx, path).Run()).To(m.Succeed())
		g.GinkgoWriter.Printf("Executed signed /bin/true on %s/%s\n", runtime.GOOS, runtime.GOARCH)
	})

	g.It("Given executable permissions, then signing preserves them on any host", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		m.Expect(os.Chmod(path, 0o751)).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		info, err := os.Stat(path)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(info.Mode().Perm()).To(m.Equal(os.FileMode(0o751)))
	})

	g.It("Given no external tools, when signing and verifying, then neither requires objcopy", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		sv := newSignerVerifier(ctx)
		g.GinkgoT().Setenv("PATH", "")
		m.Expect(inhouse.Sign(ctx, sv, path)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
	})

	g.It("Given a replaced signature, then only the active section controls verification", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFileWithOutdatedSignature))
		old := readFile(path)
		before := parseTestELF(old)
		stale := before.Section(".note.delivery-kit.signature")
		m.Expect(stale).NotTo(m.BeNil())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		data := readFile(path)
		m.Expect(data[stale.Offset : stale.Offset+stale.FileSize]).To(m.Equal(old[stale.Offset : stale.Offset+stale.FileSize]))
		data[stale.Offset] ^= 0xff
		m.Expect(os.WriteFile(path, data, 0o600)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
		active := parseTestELF(data).Section(".note.delivery-kit.signature")
		data[active.Offset+36] ^= 1
		m.Expect(os.WriteFile(path, data, 0o600)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.HaveOccurred())
	})

	g.It("Given signed content, when a hashed byte changes, then verification fails", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
		data := readFile(path)
		text := parseTestELF(data).Section(".text")
		data[text.Offset] ^= 1
		m.Expect(os.WriteFile(path, data, 0o600)).To(m.Succeed())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.MatchError(m.ContainSubstring("signature verification")))
	})

	g.It("Given a canceled operation, then the input and directory remain unchanged", func(ctx g.SpecContext) {
		original := readFile(helloElfFile)
		path := writeELF(original)
		sv := newSignerVerifier(ctx)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		m.Expect(inhouse.Sign(canceled, sv, path)).To(m.MatchError(context.Canceled))
		m.Expect(inhouse.Verify(canceled, []string{cert_utils.RootCABase64}, path)).To(m.MatchError(context.Canceled))
		m.Expect(readFile(path)).To(m.Equal(original))
		assertNoTempFiles(path)
	})

	g.It("Given a symlink, when signing, then its target is replaced and the link survives", func(ctx g.SpecContext) {
		path := writeELF(readFile(helloElfFile))
		link := filepath.Join(filepath.Dir(path), "link")
		m.Expect(os.Symlink(path, link)).To(m.Succeed())
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), link)).To(m.Succeed())
		info, err := os.Lstat(link)
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(info.Mode() & os.ModeSymlink).NotTo(m.BeZero())
		m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.Succeed())
	})

	g.DescribeTable("Given malformed metadata, when signing or verifying, then reject without modifying the input",
		func(ctx g.SpecContext, mutate func([]byte)) {
			data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
			mutate(data)
			path := writeELF(data)
			m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.HaveOccurred())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.HaveOccurred())
			m.Expect(readFile(path)).To(m.Equal(data))
			assertNoTempFiles(path)
		},
		g.Entry("section zero type", func(b []byte) { binary.LittleEndian.PutUint32(b[516:520], uint32(elf.SHT_PROGBITS)) }),
		g.Entry("section zero offset", func(b []byte) { binary.LittleEndian.PutUint64(b[536:544], 1) }),
		g.Entry("unused extended count", func(b []byte) { binary.LittleEndian.PutUint64(b[544:552], 1) }),
		g.Entry("section data outside file", func(b []byte) { binary.LittleEndian.PutUint64(b[600:608], ^uint64(0)) }),
		g.Entry("section name outside table", func(b []byte) { binary.LittleEndian.PutUint32(b[576:580], 0xffffffff) }),
		g.Entry("compressed names", func(b []byte) { binary.LittleEndian.PutUint64(b[648:656], uint64(elf.SHF_COMPRESSED)) }),
		g.Entry("oversized names", func(b []byte) { binary.LittleEndian.PutUint64(b[672:680], 65<<20) }),
		g.Entry("oversized extended count", func(b []byte) {
			binary.LittleEndian.PutUint16(b[60:62], 0)
			binary.LittleEndian.PutUint64(b[544:552], 1<<30)
		}),
	)

	g.It("Given hostile name alignment, then output limit rejects the edit without replacing the input", func(ctx g.SpecContext) {
		data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		binary.LittleEndian.PutUint64(data[688:696], 1<<28)
		path := writeELF(data)
		m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.MatchError(m.ContainSubstring("output exceeds")))
		m.Expect(readFile(path)).To(m.Equal(data))
		assertNoTempFiles(path)
	})

	g.DescribeTable("Given malformed note fields, then verification rejects the active note",
		func(ctx g.SpecContext, mutate func([]byte, uint64)) {
			path := writeELF(readFile(helloElfFile))
			m.Expect(inhouse.Sign(ctx, newSignerVerifier(ctx), path)).To(m.Succeed())
			data := readFile(path)
			section := parseTestELF(data).Section(".note.delivery-kit.signature")
			mutate(data, section.Offset)
			m.Expect(os.WriteFile(path, data, 0o600)).To(m.Succeed())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.HaveOccurred())
		},
		g.Entry("name overflow", func(b []byte, off uint64) { binary.LittleEndian.PutUint32(b[off:off+4], 0xffffffff) }),
		g.Entry("descriptor overflow", func(b []byte, off uint64) { binary.LittleEndian.PutUint32(b[off+4:off+8], 0xffffffff) }),
		g.Entry("wrong type", func(b []byte, off uint64) { b[off+8] ^= 1 }),
		g.Entry("wrong owner", func(b []byte, off uint64) { b[off+12] ^= 1 }),
		g.Entry("null bundle", func(b []byte, off uint64) { binary.LittleEndian.PutUint32(b[off+4:off+8], 4); copy(b[off+36:], "null") }),
	)

	g.It("Given every truncated prefix of an ELF, then neither entry point panics or accepts it", func(ctx g.SpecContext) {
		data := minimalELF(elf.ELFCLASS64, binary.LittleEndian, elf.EM_X86_64)
		sv := newSignerVerifier(ctx)
		for n := 0; n < len(data); n++ {
			path := writeELF(data[:n])
			m.Expect(inhouse.Sign(ctx, sv, path)).To(m.HaveOccurred())
			m.Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, path)).To(m.HaveOccurred())
			m.Expect(readFile(path)).To(m.Equal(data[:n]))
		}
	})
})
