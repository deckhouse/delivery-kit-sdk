package elf

import "errors"

var (
	ErrNotELF             = errors.New("not an ELF file")
	ErrNoSignatureSection = errors.New("no signature section")
)
