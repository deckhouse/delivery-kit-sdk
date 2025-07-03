package elf

/*
#cgo CFLAGS: -I../../../c/lib/welf/include
#cgo LDFLAGS: -L../../../cmake-build-release/c/lib/welf -L../../../cmake-build-debug/c/lib/welf -lwelf -lelf
#include <errno.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <welf.h>
#include <werror.h>

int go_elf_init(const char* elf_path, FILE** out_file, Elf** out_elf) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
        return -1;
    }

    FILE* file = fopen(elf_path, "r");
    if (!file) {
        fprintf(stderr, "failed to open file %s: %s\n", elf_path, strerror(errno));
        return -1;
    }

    Elf* elf = elf_begin(fileno(file), ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "get elf file failed: %s\n", elf_errmsg(-1));
        fclose(file);
        return -1;
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        fprintf(stderr, "file %s is not an ELF file\n", elf_path);
        elf_end(elf);
        fclose(file);
        return -1;
    }

    *out_file = file;
    *out_elf = elf;

    return 0;
}

int go_elf_compute_hash_and_grab_signature(FILE* file, Elf* elf, char** out_hash, unsigned char** out_sig, size_t* out_sig_size) {
    char* hash = compute_elf_hash(elf);
    if (!hash) {
        fprintf(stderr, "compute_elf_hash failed: %s\n", welf_errmsg());
        return -1;
    }

    if (get_elf_signature(elf, out_sig, out_sig_size) < 0) {
        fprintf(stderr, "get_elf_signature failed: %s\n", welf_errmsg());
        return -1;
    }

    *out_hash = hash;

    return 0;
}
*/
import "C"
import (
	"bytes"
	"context"
	"fmt"
	"unsafe"

	"github.com/sigstore/sigstore/pkg/signature"
)

func Sign(ctx context.Context, signerVerifier signature.SignerVerifier, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cFile *C.FILE
	var cElf *C.Elf
	if code := C.go_elf_init(cPath, &cFile, &cElf); code < 0 {
		return fmt.Errorf("ELF init failed")
	}
	defer C.elf_end(cElf)
	defer C.fclose(cFile)

	var cNewHash *C.char
	var cOldSignatureBuf *C.uchar
	var cOldSignatureSize C.size_t
	if code := C.go_elf_compute_hash_and_grab_signature(cFile, cElf, &cNewHash, &cOldSignatureBuf, &cOldSignatureSize); code < 0 {
		return fmt.Errorf("compute hash and grab signature failed")
	}
	defer C.free(unsafe.Pointer(cNewHash))

	var oldSignature []byte
	if cOldSignatureBuf != nil {
		defer C.free(unsafe.Pointer(cOldSignatureBuf))
		oldSignature = C.GoBytes(unsafe.Pointer(cOldSignatureBuf), C.int(cOldSignatureSize))
	}

	hash := C.GoString(cNewHash)
	newSignature, err := signerVerifier.SignMessage(bytes.NewReader([]byte(hash)))
	if err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	if bytes.Equal(oldSignature, newSignature) {
		return nil
	}

	cNewSignature := unsafe.Pointer(C.CBytes(newSignature))
	defer C.free(cNewSignature)

	if code := C.save_elf_signature_via_objcopy(cNewSignature, C.size_t(len(newSignature)), cPath); code < 0 {
		return fmt.Errorf("saving ELF signature failed")
	}

	return nil
}

func Verify(ctx context.Context, path string) error {
	panic("not implemented yet")
}

func Fixme() {
	fmt.Printf("FIXME\n")
}
