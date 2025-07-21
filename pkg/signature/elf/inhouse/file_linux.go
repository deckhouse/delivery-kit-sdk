//go:build linux
// +build linux

package inhouse

/*
#cgo CFLAGS: -I../../../../c/lib/welf/include -I../../../../c/vendor/libelf/include
#cgo LDFLAGS: -L../../../../c/lib -L../../../../c/vendor -l:welf.a -lelf -luv_a -lzstd -lz -lssl -lcrypto -ldl -lpthread -static
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
        return -2;
    }

    *out_file = file;
    *out_elf = elf;

    return 0;
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

//go:generate sh -c "cmake -S ../../../../c/lib/welf -B ../../../../c/lib/welf/build -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release} && cmake --build ../../../../c/lib/welf/build"

var ErrNotELF = errors.New("not an ELF file")

func Sign(ctx context.Context, signerVerifier *signver.SignerVerifier, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cFile, cElf, err := initELF(cPath)
	if err != nil {
		return err
	}
	defer C.elf_end(cElf)
	defer C.fclose(cFile)

	var cNewHashBuf *C.char
	var cNewHashSize C.size_t
	if C.welf_compute_elf_hash(cElf, &cNewHashBuf, &cNewHashSize) < 0 {
		return fmt.Errorf("compute elf hash failed: %s", C.GoString(C.welf_errmsg()))
	}
	defer C.free(unsafe.Pointer(cNewHashBuf))

	// var cOldSignatureBundleBuf *C.uchar
	// var cOldSignatureBundleSize C.size_t
	// if C.welf_get_elf_signature(cElf, &cOldSignatureBundleBuf, &cOldSignatureBundleSize) < 0 {
	// 	return fmt.Errorf("get elf signature failed: %s", C.GoString(C.welf_errmsg()))
	// }

	hashBytes := C.GoBytes(unsafe.Pointer(cNewHashBuf), C.int(cNewHashSize))

	// if cOldSignatureBundleBuf != nil {
	// 	defer C.free(unsafe.Pointer(cOldSignatureBundleBuf))
	// 	oldSignatureBundleBytes := C.GoBytes(unsafe.Pointer(cOldSignatureBundleBuf), C.int(cOldSignatureBundleSize))
	//
	// 	var oldSignatureBundle *signature.Bundle
	// 	if err := json.Unmarshal(oldSignatureBundleBytes, &oldSignatureBundle); err != nil {
	// 		return fmt.Errorf("unmarshal old signature bundle: %w", err)
	// 	}
	//
	// 	if err := signature.VerifyBundle(ctx, *oldSignatureBundle, string(hashBytes), rootCertRef); err != nil {
	// 		if !errors.Is(err, rsa.ErrVerification) {
	// 			return fmt.Errorf("verify old signature bundle, but with a new hash: %w", err)
	// 		}
	// 	} else {
	// 		return nil
	// 	}
	// }

	newSignatureBundle, err := signature.Sign(ctx, signerVerifier, string(hashBytes))
	if err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}

	newSignatureBundleBytes, err := json.Marshal(newSignatureBundle)
	if err != nil {
		return fmt.Errorf("marshal new signature bundle: %w", err)
	}

	cNewSignatureBundleBytes := unsafe.Pointer(C.CBytes(newSignatureBundleBytes))
	defer C.free(cNewSignatureBundleBytes)

	if code := C.welf_save_elf_signature_via_objcopy(cElf, cNewSignatureBundleBytes, C.size_t(len(newSignatureBundleBytes)), cPath); code < 0 {
		return fmt.Errorf("saving ELF signature failed: %s", C.GoString(C.go_errmsg()))
	}

	return nil
}

func Verify(ctx context.Context, rootCertRef, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cFile, cElf, err := initELF(cPath)
	if err != nil {
		return err
	}
	defer C.elf_end(cElf)
	defer C.fclose(cFile)

	var cHashBuf *C.char
	var cHashSize C.size_t
	if C.welf_compute_elf_hash(cElf, &cHashBuf, &cHashSize) < 0 {
		return fmt.Errorf("compute elf hash failed: %s", C.GoString(C.welf_errmsg()))
	}
	defer C.free(unsafe.Pointer(cHashBuf))

	var cSignatureBundleBuf *C.uchar
	var cSignatureBundleSize C.size_t
	if C.welf_get_elf_signature(cElf, &cSignatureBundleBuf, &cSignatureBundleSize) < 0 {
		return fmt.Errorf("get elf signature failed: %s", C.GoString(C.welf_errmsg()))
	}
	signatureBundleBytes := []byte{}
	if cSignatureBundleBuf != nil {
		defer C.free(unsafe.Pointer(cSignatureBundleBuf))
		signatureBundleBytes = C.GoBytes(unsafe.Pointer(cSignatureBundleBuf), C.int(cSignatureBundleSize))
	}

	hashBytes := C.GoBytes(unsafe.Pointer(cHashBuf), C.int(cHashSize))

	var signatureBundle *signature.Bundle
	if err := json.Unmarshal(signatureBundleBytes, &signatureBundle); err != nil {
		return fmt.Errorf("unmarshal signature bundle: %w", err)
	}

	// TODO:
	// if signatureBundle.ApiVersion != SignatureDataApiVersionV1 {
	//     return fmt.Errorf("unsupported signature data API version: %s", signatureBundle.ApiVersion)
	// }

	if err := signature.VerifyBundle(ctx, *signatureBundle, string(hashBytes), rootCertRef); err != nil {
		return fmt.Errorf("verify signature bundle: %w", err)
	}

	return nil
}

func initELF(cPath *C.char) (*C.FILE, *C.Elf, error) {
	var cFile *C.FILE
	var cElf *C.Elf
	if code := C.go_elf_init(cPath, &cFile, &cElf); code < 0 {
		if code == -2 {
			return nil, nil, ErrNotELF
		}
		return nil, nil, fmt.Errorf("ELF init failed: %s", C.GoString(C.go_errmsg()))
	}
	
	return cFile, cElf, nil
}