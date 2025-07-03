//go:build linux
// +build linux

package elf

/*
#cgo CFLAGS: -I../../../c/lib/welf/include -I../../../c/vendor/libelf/include
#cgo LDFLAGS: -L../../../c/lib/welf/build -L../../../c/vendor/libelf -lwelf -lelf -luv_a -lzstd -lz -lssl -lcrypto -ldl -lpthread -static
#include <errno.h>
#include <libelf.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <welf_elf.h>
#include <welf_error.h>

static char go_errmsg_buf[1024];

void go_set_errmsg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(go_errmsg_buf, sizeof(go_errmsg_buf), fmt, args);
    va_end(args);
}

const char* go_errmsg() {
    return go_errmsg_buf;
}

int go_elf_init(const char* elf_path, FILE** out_file, Elf** out_elf) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        go_set_errmsg("libelf initialization failed: %s", elf_errmsg(-1));
        return -1;
    }

    FILE* file = fopen(elf_path, "r");
    if (!file) {
        go_set_errmsg("failed to open file %s: %s", elf_path, strerror(errno));
        return -1;
    }

    Elf* elf = elf_begin(fileno(file), ELF_C_READ, NULL);
    if (!elf) {
        go_set_errmsg("get elf file failed: %s", elf_errmsg(-1));
        fclose(file);
        return -1;
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        go_set_errmsg("file %s is not an ELF file", elf_path);
        elf_end(elf);
        fclose(file);
        return -1;
    }

    *out_file = file;
    *out_elf = elf;

    return 0;
}

int go_elf_compute_hash_and_grab_signature(FILE* file, Elf* elf, char** out_hash, unsigned char** out_sig, size_t* out_sig_size) {
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    if (welf_compute_elf_hash(elf, hash) < 0) {
        go_set_errmsg("compute_elf_hash failed: %s", "unknown error");
        return -1;
    }

    if (welf_get_elf_signature(elf, out_sig, out_sig_size) < 0) {
        go_set_errmsg("get_elf_signature failed: %s", welf_errmsg());
        return -1;
    }

    *out_hash = strdup(hash);

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

//go:generate sh -c "cmake -S ../../../c/lib/welf -B ../../../c/lib/welf/build -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release} && cmake --build ../../../c/lib/welf/build"

func Sign(ctx context.Context, signerVerifier signature.SignerVerifier, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cFile *C.FILE
	var cElf *C.Elf
	if code := C.go_elf_init(cPath, &cFile, &cElf); code < 0 {
		return fmt.Errorf("ELF init failed: %s", C.GoString(C.go_errmsg()))
	}
	defer C.elf_end(cElf)
	defer C.fclose(cFile)

	var cNewHash *C.char
	var cOldSignatureBuf *C.uchar
	var cOldSignatureSize C.size_t
	if code := C.go_elf_compute_hash_and_grab_signature(cFile, cElf, &cNewHash, &cOldSignatureBuf, &cOldSignatureSize); code < 0 {
		return fmt.Errorf("compute hash and grab signature failed: %s", C.GoString(C.go_errmsg()))
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

	if code := C.welf_save_elf_signature_via_objcopy(cNewSignature, C.size_t(len(newSignature)), cPath); code < 0 {
		return fmt.Errorf("saving ELF signature failed: %s", C.GoString(C.go_errmsg()))
	}

	return nil
}

func Verify(ctx context.Context, path string) error {
	panic("not implemented yet")
}
