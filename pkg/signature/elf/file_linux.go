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
*/
import "C"
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

//go:generate sh -c "cmake -S ../../../c/lib/welf -B ../../../c/lib/welf/build -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release} && cmake --build ../../../c/lib/welf/build"

func Sign(ctx context.Context, path string, signerVerifier *signver.SignerVerifier) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cFile *C.FILE
	var cElf *C.Elf
	if code := C.go_elf_init(cPath, &cFile, &cElf); code < 0 {
		return fmt.Errorf("ELF init failed: %s", C.GoString(C.go_errmsg()))
	}
	defer C.elf_end(cElf)
	defer C.fclose(cFile)

	var cNewHashBuf *C.char
	var cNewHashSize C.size_t
	if C.welf_compute_elf_hash(cElf, &cNewHashBuf, &cNewHashSize) < 0 {
		return fmt.Errorf("compute elf hash failed: %s", C.GoString(C.welf_errmsg()))
	}
	defer C.free(unsafe.Pointer(cNewHashBuf))

	var cOldSignatureDataBuf *C.uchar
	var cOldSignatureDataSize C.size_t
	if C.welf_get_elf_signature(cElf, &cOldSignatureDataBuf, &cOldSignatureDataSize) < 0 {
		return fmt.Errorf("get elf signature failed: %s", C.GoString(C.welf_errmsg()))
	}
	var oldSignatureDataBytes []byte
	if cOldSignatureDataBuf != nil {
		defer C.free(unsafe.Pointer(cOldSignatureDataBuf))
		oldSignatureDataBytes = C.GoBytes(unsafe.Pointer(cOldSignatureDataBuf), C.int(cOldSignatureDataSize))
	}

	hashBytes := C.GoBytes(unsafe.Pointer(cNewHashBuf), C.int(cNewHashSize))
	newSignatureBytes, err := signerVerifier.SignMessage(bytes.NewReader(hashBytes))
	if err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	newSignatureData := &SignatureData{
		Signature: newSignatureBytes,
		Cert:      signerVerifier.Cert,
	}

	newSignatureDataBytes, err := json.Marshal(newSignatureData)
	if err != nil {
		return fmt.Errorf("marshal new signature data: %w", err)
	}

	if bytes.Equal(oldSignatureDataBytes, newSignatureDataBytes) {
		return nil
	}

	cNewSignatureDataBytes := unsafe.Pointer(C.CBytes(newSignatureDataBytes))
	defer C.free(cNewSignatureDataBytes)

	if code := C.welf_save_elf_signature_via_objcopy(cNewSignatureDataBytes, C.size_t(len(newSignatureDataBytes)), cPath); code < 0 {
		return fmt.Errorf("saving ELF signature failed: %s", C.GoString(C.go_errmsg()))
	}

	return nil
}

// FIXME(ilya-lesikov): signerVerifier doesn't respect cert saved in signature.
func Verify(ctx context.Context, path string, signerVerifier *signver.SignerVerifier) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var cFile *C.FILE
	var cElf *C.Elf
	if code := C.go_elf_init(cPath, &cFile, &cElf); code < 0 {
		return fmt.Errorf("ELF init failed: %s", C.GoString(C.go_errmsg()))
	}
	defer C.elf_end(cElf)
	defer C.fclose(cFile)

	var cHashBuf *C.char
	var cHashSize C.size_t
	if C.welf_compute_elf_hash(cElf, &cHashBuf, &cHashSize) < 0 {
		return fmt.Errorf("compute elf hash failed: %s", C.GoString(C.welf_errmsg()))
	}
	defer C.free(unsafe.Pointer(cHashBuf))

	var cSignatureDataBuf *C.uchar
	var cSignatureDataSize C.size_t
	if C.welf_get_elf_signature(cElf, &cSignatureDataBuf, &cSignatureDataSize) < 0 {
		return fmt.Errorf("get elf signature failed: %s", C.GoString(C.welf_errmsg()))
	}
	signatureDataBytes := []byte{}
	if cSignatureDataBuf != nil {
		defer C.free(unsafe.Pointer(cSignatureDataBuf))
		signatureDataBytes = C.GoBytes(unsafe.Pointer(cSignatureDataBuf), C.int(cSignatureDataSize))
	}

	hashBytes := C.GoBytes(unsafe.Pointer(cHashBuf), C.int(cHashSize))

	var signatureData *SignatureData
	if err := json.Unmarshal(signatureDataBytes, &signatureData); err != nil {
		return fmt.Errorf("unmarshal signature data: %w", err)
	}

	signatureData.Cert

	if err := signerVerifier.VerifySignature(bytes.NewReader(signatureData.Signature), bytes.NewReader(hashBytes)); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	return nil
}

type SignatureData struct {
	Signature []byte `json:"io.deckhouse.deliverykit.signature"`
	Cert      []byte `json:"io.deckhouse.deliverykit.cert"`
}
