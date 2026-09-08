package inhouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	elfsig "github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
)

const maxMetadataSize = 64 << 20

type elfFile struct {
	src            io.ReaderAt
	size           uint64
	order          binary.ByteOrder
	class          elf.Class
	sections       []elf.Section64
	names          []byte
	phoff          uint64
	phnum          uint64
	phentsize      uint64
	signatureIndex int
}

func readELF(ctx context.Context, src io.ReaderAt, size int64) (*elfFile, error) {
	var ident [16]byte
	n, err := src.ReadAt(ident[:], 0)
	if n < 4 || string(ident[:4]) != elf.ELFMAG {
		return nil, elfsig.ErrNotELF
	}
	if err != nil {
		return nil, fmt.Errorf("read ELF identification: %w", err)
	}
	f := &elfFile{src: src, size: uint64(size), class: elf.Class(ident[elf.EI_CLASS])}
	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		f.order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		f.order = binary.BigEndian
	default:
		return nil, fmt.Errorf("invalid ELF byte order")
	}
	var shoff, shnum, shstrndx, shentsize uint64
	var ehsize uint16
	var version uint32
	switch f.class {
	case elf.ELFCLASS32:
		var h elf.Header32
		if err := f.read(0, &h); err != nil {
			return nil, err
		}
		shoff, shnum, shstrndx, shentsize = uint64(h.Shoff), uint64(h.Shnum), uint64(h.Shstrndx), uint64(h.Shentsize)
		f.phoff, f.phnum, f.phentsize = uint64(h.Phoff), uint64(h.Phnum), uint64(h.Phentsize)
		ehsize, version = h.Ehsize, h.Version
		if ehsize != 52 || shentsize != 40 && shoff != 0 {
			return nil, fmt.Errorf("invalid ELF32 header sizes")
		}
	case elf.ELFCLASS64:
		var h elf.Header64
		if err := f.read(0, &h); err != nil {
			return nil, err
		}
		shoff, shnum, shstrndx, shentsize = h.Shoff, uint64(h.Shnum), uint64(h.Shstrndx), uint64(h.Shentsize)
		f.phoff, f.phnum, f.phentsize = h.Phoff, uint64(h.Phnum), uint64(h.Phentsize)
		ehsize, version = h.Ehsize, h.Version
		if ehsize != 64 || shentsize != 64 && shoff != 0 {
			return nil, fmt.Errorf("invalid ELF64 header sizes")
		}
	default:
		return nil, fmt.Errorf("invalid ELF class")
	}
	if ident[elf.EI_VERSION] != byte(elf.EV_CURRENT) || version != uint32(elf.EV_CURRENT) {
		return nil, fmt.Errorf("invalid ELF version")
	}
	if shoff == 0 && shnum == 0 {
		return nil, elfsig.ErrNoSections
	}
	if shoff < uint64(ehsize) {
		return nil, fmt.Errorf("invalid section table offset")
	}
	zero, err := f.section(shoff)
	if err != nil {
		return nil, err
	}
	if zero.Type != uint32(elf.SHT_NULL) || zero.Name != 0 || zero.Flags != 0 || zero.Addr != 0 || zero.Off != 0 || zero.Addralign != 0 || zero.Entsize != 0 {
		return nil, fmt.Errorf("invalid section zero")
	}
	if shnum != 0 && zero.Size != 0 || shstrndx != uint64(elf.SHN_XINDEX) && zero.Link != 0 || f.phnum != 0xffff && zero.Info != 0 {
		return nil, fmt.Errorf("unused extended ELF counts")
	}
	if shnum == 0 {
		shnum = zero.Size
	}
	if shstrndx == uint64(elf.SHN_XINDEX) {
		shstrndx = uint64(zero.Link)
	}
	if shnum == 0 || shnum > maxMetadataSize/64 || !f.contains(shoff, shnum*shentsize) {
		return nil, fmt.Errorf("section table exceeds file or metadata limit")
	}
	if shstrndx == 0 || shstrndx >= shnum {
		return nil, fmt.Errorf("invalid section name table index")
	}
	f.sections = make([]elf.Section64, int(shnum))
	for i := range f.sections {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, err := f.section(shoff + uint64(i)*shentsize)
		if err != nil {
			return nil, err
		}
		if i != 0 && s.Type != uint32(elf.SHT_NOBITS) && s.Type != uint32(elf.SHT_NULL) && !f.contains(s.Off, s.Size) {
			return nil, fmt.Errorf("section %d outside file", i)
		}
		f.sections[i] = s
	}
	str := f.sections[shstrndx]
	if str.Type != uint32(elf.SHT_STRTAB) || str.Flags&uint64(elf.SHF_COMPRESSED) != 0 || str.Size == 0 || str.Size > maxMetadataSize-shnum*64 {
		return nil, fmt.Errorf("invalid or oversized section name table")
	}
	f.names = make([]byte, int(str.Size))
	if _, err := src.ReadAt(f.names, int64(str.Off)); err != nil {
		return nil, fmt.Errorf("read section names: %w", err)
	}
	if f.names[0] != 0 || f.names[len(f.names)-1] != 0 {
		return nil, fmt.Errorf("unterminated section name table")
	}
	for i, s := range f.sections {
		if i == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if uint64(s.Name) >= uint64(len(f.names)) {
			return nil, fmt.Errorf("section name outside table")
		}
		if f.named(s, signatureSectionName) {
			if f.signatureIndex != 0 {
				return nil, fmt.Errorf("duplicate signature section")
			}
			if s.Type != uint32(elf.SHT_NOTE) || s.Flags&uint64(elf.SHF_ALLOC|elf.SHF_COMPRESSED) != 0 {
				return nil, fmt.Errorf("invalid signature section attributes")
			}
			f.signatureIndex = i
		}
	}
	actualPhnum := f.phnum
	if actualPhnum == 0xffff {
		actualPhnum = uint64(zero.Info)
	}
	if actualPhnum > 0 {
		expectedSize := uint64(56)
		if f.class == elf.ELFCLASS32 {
			expectedSize = 32
		}
		if actualPhnum > maxMetadataSize/56 || f.phentsize != expectedSize || f.phoff < uint64(ehsize) || !f.contains(f.phoff, actualPhnum*f.phentsize) {
			return nil, fmt.Errorf("program table exceeds file or metadata limit")
		}
		for i := uint64(0); i < actualPhnum; i++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			p, err := f.program(i)
			if err != nil {
				return nil, err
			}
			if !f.contains(p.Off, p.Filesz) {
				return nil, fmt.Errorf("program segment outside file")
			}
		}
	}
	return f, nil
}

func (f *elfFile) contains(offset, size uint64) bool {
	return offset <= f.size && size <= f.size-offset
}

func (f *elfFile) read(offset uint64, value any) error {
	n := binary.Size(value)
	if !f.contains(offset, uint64(n)) {
		return fmt.Errorf("ELF metadata outside file")
	}
	if err := binary.Read(io.NewSectionReader(f.src, int64(offset), int64(n)), f.order, value); err != nil {
		return fmt.Errorf("read ELF metadata: %w", err)
	}
	return nil
}

func (f *elfFile) section(offset uint64) (elf.Section64, error) {
	var s elf.Section64
	if f.class == elf.ELFCLASS64 {
		err := f.read(offset, &s)
		return s, err
	}
	var s32 elf.Section32
	if err := f.read(offset, &s32); err != nil {
		return s, err
	}
	return elf.Section64{Name: s32.Name, Type: s32.Type, Flags: uint64(s32.Flags), Addr: uint64(s32.Addr), Off: uint64(s32.Off), Size: uint64(s32.Size), Link: s32.Link, Info: s32.Info, Addralign: uint64(s32.Addralign), Entsize: uint64(s32.Entsize)}, nil
}

func (f *elfFile) program(index uint64) (elf.Prog64, error) {
	var p elf.Prog64
	offset := f.phoff + index*f.phentsize
	if f.class == elf.ELFCLASS64 {
		err := f.read(offset, &p)
		return p, err
	}
	var p32 elf.Prog32
	if err := f.read(offset, &p32); err != nil {
		return p, err
	}
	return elf.Prog64{Type: p32.Type, Flags: p32.Flags, Off: uint64(p32.Off), Vaddr: uint64(p32.Vaddr), Paddr: uint64(p32.Paddr), Filesz: uint64(p32.Filesz), Memsz: uint64(p32.Memsz), Align: uint64(p32.Align)}, nil
}

func (f *elfFile) named(s elf.Section64, name string) bool {
	start := uint64(s.Name)
	end := start + uint64(len(name))
	return end < uint64(len(f.names)) && f.names[end] == 0 && bytes.Equal(f.names[start:end], []byte(name))
}

func (f *elfFile) hash(ctx context.Context) (string, error) {
	return f.hashOrder(ctx, binary.NativeEndian)
}

func (f *elfFile) hashOrder(ctx context.Context, order binary.ByteOrder) (string, error) {
	h := sha256.New()
	// Legacy libelf hashed host-memory GElf (ELF64) structures, even for ELF32
	// and big-endian artifacts. This order belongs to the signing host, not the ELF.
	for i := uint64(0); i < f.phnum; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		p, err := f.program(i)
		if err != nil {
			return "", err
		}
		if err := binary.Write(h, order, elf.Prog64{Type: p.Type, Flags: p.Flags}); err != nil {
			return "", fmt.Errorf("hash program header: %w", err)
		}
	}
	buf := make([]byte, 64*1024)
	for i, s := range f.sections {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if i == 0 {
			continue
		}
		if f.named(s, signatureSectionName) || f.named(s, "signature") || f.named(s, ".shstrtab") || s.Type == uint32(elf.SHT_NOBITS) {
			continue
		}
		if err := binary.Write(h, order, elf.Section64{Name: s.Name, Type: s.Type, Flags: s.Flags}); err != nil {
			return "", fmt.Errorf("hash section header: %w", err)
		}
		for offset := uint64(0); offset < s.Size; {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			n := min(uint64(len(buf)), s.Size-offset)
			if _, err := f.src.ReadAt(buf[:n], int64(s.Off+offset)); err != nil {
				return "", fmt.Errorf("read hashed section: %w", err)
			}
			if _, err := h.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("hash section: %w", err)
			}
			offset += n
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
