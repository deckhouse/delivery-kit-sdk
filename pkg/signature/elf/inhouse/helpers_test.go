package inhouse_test

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
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
