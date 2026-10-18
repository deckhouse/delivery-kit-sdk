package inhouse_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	g "github.com/onsi/ginkgo/v2"
	m "github.com/onsi/gomega"
	sigstore "github.com/sigstore/sigstore/pkg/signature"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

func writeELF(data []byte) string {
	path := filepath.Join(g.GinkgoT().TempDir(), "artifact")
	m.Expect(os.WriteFile(path, data, 0o700)).To(m.Succeed())
	return path
}

func assertNoTempFiles(path string) {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".delivery-kit-sign-*"))
	m.Expect(err).NotTo(m.HaveOccurred())
	m.Expect(matches).To(m.BeEmpty())
}

func minimalELF(class elf.Class, order binary.ByteOrder, machine elf.Machine) []byte {
	var ident [16]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS], ident[elf.EI_VERSION] = byte(class), byte(elf.EV_CURRENT)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	if order == binary.BigEndian {
		ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	var out bytes.Buffer
	names := []byte("\x00.text\x00.shstrtab\x00")
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x400100, Off: 256, Size: 4, Addralign: 4},
		{Name: 7, Type: uint32(elf.SHT_STRTAB), Off: 320, Size: uint64(len(names)), Addralign: 1},
	}
	if class == elf.ELFCLASS64 {
		m.Expect(binary.Write(&out, order, elf.Header64{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Entry: 0x400100, Phoff: 64, Shoff: 512, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64, Shnum: 3, Shstrndx: 2})).To(m.Succeed())
		m.Expect(binary.Write(&out, order, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: 0, Vaddr: 0x400000, Paddr: 0x400000, Filesz: 260, Memsz: 260, Align: 4096})).To(m.Succeed())
	} else {
		m.Expect(binary.Write(&out, order, elf.Header32{Ident: ident, Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: 1, Entry: 0x400100, Phoff: 52, Shoff: 512, Ehsize: 52, Phentsize: 32, Phnum: 1, Shentsize: 40, Shnum: 3, Shstrndx: 2})).To(m.Succeed())
		m.Expect(binary.Write(&out, order, elf.Prog32{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: 0, Vaddr: 0x400000, Paddr: 0x400000, Filesz: 260, Memsz: 260, Align: 4096})).To(m.Succeed())
	}
	out.Write(make([]byte, 512-out.Len()))
	copy(out.Bytes()[256:], []byte{1, 2, 3, 4})
	copy(out.Bytes()[320:], names)
	for _, s := range sections {
		if class == elf.ELFCLASS64 {
			m.Expect(binary.Write(&out, order, s)).To(m.Succeed())
		} else {
			m.Expect(binary.Write(&out, order, elf.Section32{Name: s.Name, Type: s.Type, Flags: uint32(s.Flags), Addr: uint32(s.Addr), Off: uint32(s.Off), Size: uint32(s.Size), Addralign: uint32(s.Addralign)})).To(m.Succeed())
		}
	}
	return out.Bytes()
}

func assertLoadPreserved(before, after []byte) {
	f, updated := parseTestELF(before), parseTestELF(after)
	m.Expect(updated.FileHeader).To(m.Equal(f.FileHeader))
	m.Expect(updated.Progs).To(m.HaveLen(len(f.Progs)))
	masked := bytes.Clone(after[:len(before)])
	if f.Class == elf.ELFCLASS64 {
		copy(masked[40:48], before[40:48])
		copy(masked[58:64], before[58:64])
	} else {
		copy(masked[32:36], before[32:36])
		copy(masked[46:52], before[46:52])
	}
	m.Expect(masked).To(m.Equal(before))
	for i, p := range f.Progs {
		m.Expect(updated.Progs[i].ProgHeader).To(m.Equal(p.ProgHeader))
		m.Expect(masked[p.Off : p.Off+p.Filesz]).To(m.Equal(before[p.Off : p.Off+p.Filesz]))
	}
}

func parseTestELF(data []byte) *elf.File {
	f, err := elf.NewFile(bytes.NewReader(data))
	m.Expect(err).NotTo(m.HaveOccurred())
	return f
}

func legacyCommand(ctx context.Context, action, path string, extra ...string) []byte {
	args := append([]string{action, path}, extra...)
	out, err := exec.CommandContext(ctx, os.Getenv("ELF_LEGACY_TOOL"), args...).CombinedOutput()
	m.Expect(err).NotTo(m.HaveOccurred(), "%s: %s", action, out)
	return out
}

func legacyVerify(ctx context.Context, path string) {
	digest := legacyCommand(ctx, "hash", path)
	payload := legacyCommand(ctx, "extract", path)
	var bundle signature.Bundle
	m.Expect(json.Unmarshal(payload, &bundle)).To(m.Succeed())
	m.Expect(signature.VerifyBundle(ctx, bundle, string(digest), []string{cert_utils.RootCABase64})).To(m.Succeed())
}

func newSignerVerifier(ctx g.SpecContext) *signver.SignerVerifier {
	sv, err := signver.NewSignerVerifier(ctx, cert_utils.SignerCertBase64, cert_utils.SignerChainBase64, signver.KeyOpts{KeyRef: cert_utils.SignerKeyBase64})
	m.Expect(err).NotTo(m.HaveOccurred())
	return sv
}

func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	m.Expect(err).NotTo(m.HaveOccurred())
	return data
}

func makeTempFileCopy(srcPath string) (string, func()) {
	path := writeELF(readFile(srcPath))
	return path, func() { m.Expect(os.Remove(path)).To(m.Succeed()) }
}

type hookSigner struct {
	sigstore.SignerVerifier
	after func()
}

var _ sigstore.SignerVerifier = (*hookSigner)(nil)

func (s *hookSigner) SignMessage(message io.Reader, opts ...sigstore.SignOption) ([]byte, error) {
	data, err := s.SignerVerifier.SignMessage(message, opts...)
	if err != nil {
		return nil, err
	}
	s.after()
	return data, nil
}

func stringTableELF(class elf.Class, order binary.ByteOrder, shared bool) []byte {
	data := minimalELF(class, order, elf.EM_X86_64)
	names := []byte("\x00.text\x00.shstrtab\x00.strtab\x00.symtab\x00symbol\x00")
	copy(data[320:], names)
	s := testSectionHeader(data, 2)
	s.Name, s.Size = 17, uint64(len(names))
	putTestSection(data, 2, s)
	if !shared {
		return data
	}
	var symbols bytes.Buffer
	var zero, symbol any = elf.Sym64{}, elf.Sym64{Name: 33, Info: 0x12, Shndx: 1, Value: 0x400100, Size: 4}
	entrySize := 64
	if class == elf.ELFCLASS32 {
		zero, symbol, entrySize = elf.Sym32{}, elf.Sym32{Name: 33, Info: 0x12, Shndx: 1, Value: 0x400100, Size: 4}, 40
		order.PutUint16(data[48:50], 4)
	} else {
		order.PutUint16(data[60:62], 4)
	}
	m.Expect(binary.Write(&symbols, order, zero)).To(m.Succeed())
	m.Expect(binary.Write(&symbols, order, symbol)).To(m.Succeed())
	offset := len(data) + entrySize
	data = append(data, make([]byte, entrySize)...)
	data = append(data, symbols.Bytes()...)
	putTestSection(data, 3, elf.Section64{Name: 25, Type: uint32(elf.SHT_SYMTAB), Off: uint64(offset), Size: uint64(symbols.Len()), Link: 2, Info: 1, Addralign: 8, Entsize: uint64(binary.Size(symbol))})
	return data
}

func testSectionHeader(data []byte, index int) elf.Section64 {
	f := parseTestELF(data)
	if f.Class == elf.ELFCLASS64 {
		var s elf.Section64
		offset := f.ByteOrder.Uint64(data[40:48]) + uint64(index)*64
		m.Expect(binary.Read(bytes.NewReader(data[offset:]), f.ByteOrder, &s)).To(m.Succeed())
		return s
	}
	var s elf.Section32
	offset := f.ByteOrder.Uint32(data[32:36]) + uint32(index)*40
	m.Expect(binary.Read(bytes.NewReader(data[offset:]), f.ByteOrder, &s)).To(m.Succeed())
	return elf.Section64{Name: s.Name, Type: s.Type, Flags: uint64(s.Flags), Addr: uint64(s.Addr), Off: uint64(s.Off), Size: uint64(s.Size), Link: s.Link, Info: s.Info, Addralign: uint64(s.Addralign), Entsize: uint64(s.Entsize)}
}

func putTestSection(data []byte, index int, s elf.Section64) {
	var order binary.ByteOrder = binary.LittleEndian
	if data[elf.EI_DATA] == byte(elf.ELFDATA2MSB) {
		order = binary.BigEndian
	}
	var out bytes.Buffer
	var value any = s
	offset := uint64(0)
	if data[elf.EI_CLASS] == byte(elf.ELFCLASS32) {
		offset = uint64(order.Uint32(data[32:36])) + uint64(index)*40
		value = elf.Section32{Name: s.Name, Type: s.Type, Flags: uint32(s.Flags), Addr: uint32(s.Addr), Off: uint32(s.Off), Size: uint32(s.Size), Link: s.Link, Info: s.Info, Addralign: uint32(s.Addralign), Entsize: uint32(s.Entsize)}
	} else {
		offset = order.Uint64(data[40:48]) + uint64(index)*64
	}
	m.Expect(binary.Write(&out, order, value)).To(m.Succeed())
	copy(data[offset:], out.Bytes())
}

func assertStringTablePreserved(before, after []byte) {
	original, updated := parseTestELF(before), parseTestELF(after)
	for i := 1; i < len(original.Sections); i++ {
		m.Expect(testSectionHeader(after, i)).To(m.Equal(testSectionHeader(before, i)), "section %d", i)
		m.Expect(updated.Sections[i].SectionHeader).To(m.Equal(original.Sections[i].SectionHeader))
	}
	if original.Section(".symtab") != nil {
		symbols, err := original.Symbols()
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(symbols).To(m.HaveLen(1))
		m.Expect(symbols[0].Name).To(m.Equal("symbol"))
		actual, err := updated.Symbols()
		m.Expect(err).NotTo(m.HaveOccurred())
		m.Expect(actual).To(m.Equal(symbols))
	}
	assertLoadPreserved(before, after)
}

func referenceELFDigest(data []byte, order binary.ByteOrder) string {
	f := parseTestELF(data)
	h := sha256.New()
	for _, p := range f.Progs {
		var header [56]byte
		order.PutUint32(header[:4], uint32(p.Type))
		order.PutUint32(header[4:8], uint32(p.Flags))
		_, err := h.Write(header[:])
		m.Expect(err).NotTo(m.HaveOccurred())
	}
	for i, s := range f.Sections {
		if i == 0 || s.Type == elf.SHT_NOBITS || s.Name == ".shstrtab" || s.Name == "signature" || s.Name == ".note.delivery-kit.signature" {
			continue
		}
		var header [64]byte
		order.PutUint32(header[:4], testSectionHeader(data, i).Name)
		order.PutUint32(header[4:8], uint32(s.Type))
		order.PutUint64(header[8:16], uint64(s.Flags))
		_, err := h.Write(header[:])
		m.Expect(err).NotTo(m.HaveOccurred())
		_, err = h.Write(data[s.Offset : s.Offset+s.FileSize])
		m.Expect(err).NotTo(m.HaveOccurred())
	}
	return hex.EncodeToString(h.Sum(nil))
}
