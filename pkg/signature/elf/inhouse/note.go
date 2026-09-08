package inhouse

import (
	"encoding/binary"
	"fmt"

	elfsig "github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
)

const (
	signatureSectionName = ".note.delivery-kit.signature"
	signatureNoteName    = "delivery-kit.signature\x00"
	signatureNoteType    = 0x31415926
	maxNoteSize          = 16 << 20
)

func makeNote(order binary.ByteOrder, payload []byte) ([]byte, error) {
	if len(payload) > maxNoteSize-36 {
		return nil, fmt.Errorf("signature bundle exceeds note limit")
	}
	note := make([]byte, 36+(len(payload)+3)&^3)
	order.PutUint32(note[:4], uint32(len(signatureNoteName)))
	order.PutUint32(note[4:8], uint32(len(payload)))
	order.PutUint32(note[8:12], signatureNoteType)
	copy(note[12:], signatureNoteName)
	copy(note[36:], payload)
	return note, nil
}

func (f *elfFile) signature() ([]byte, error) {
	if f.signatureIndex == 0 {
		return nil, elfsig.ErrNoSignatureSection
	}
	s := f.sections[f.signatureIndex]
	if s.Size == 0 {
		return nil, elfsig.ErrNoSignatureSection
	}
	if s.Size > maxNoteSize || s.Size < 12 {
		return nil, fmt.Errorf("invalid signature note size")
	}
	note := make([]byte, int(s.Size))
	if _, err := f.src.ReadAt(note, int64(s.Off)); err != nil {
		return nil, fmt.Errorf("read signature note: %w", err)
	}
	order := f.order
	// The former C writer used host order even when the ELF had the other order.
	if order.Uint32(note[8:12]) != signatureNoteType {
		if order == binary.BigEndian {
			order = binary.LittleEndian
		} else {
			order = binary.BigEndian
		}
	}
	namesz := uint64(order.Uint32(note[:4]))
	descsz := uint64(order.Uint32(note[4:8]))
	typ := order.Uint32(note[8:12])
	offset := 12 + (namesz+3)&^3
	if namesz == 0 || namesz > uint64(len(note))-12 || offset > uint64(len(note)) || descsz > uint64(len(note))-offset {
		return nil, fmt.Errorf("signature note fields outside section")
	}
	if typ != signatureNoteType {
		return nil, fmt.Errorf("unexpected signature note type %#x", typ)
	}
	if string(note[12:12+namesz]) != signatureNoteName {
		return nil, fmt.Errorf("unexpected signature note name")
	}
	if descsz == 0 {
		return nil, elfsig.ErrNoSignatureSection
	}
	return note[offset : offset+descsz], nil
}
