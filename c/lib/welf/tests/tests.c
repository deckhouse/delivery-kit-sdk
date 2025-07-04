#include <elf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <openssl/sha.h>

#include "welf_elf.h"
#include "welf_error.h"

int main(void) {
    const char *hello_elf_orig = "../../../../test/data/hello.elf";
    const char *hello_elf = "hello.elf";
    FILE *file = NULL;
    Elf *elf = NULL;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
        return EXIT_FAILURE;
    }

    uv_fs_t copy_req;
    int copyResult = uv_fs_copyfile(NULL, &copy_req, hello_elf_orig, hello_elf, 0, NULL);
    if (copyResult < 0) {
        fprintf(stderr, "copying file failed: %s\n", uv_strerror(copyResult));
        return EXIT_FAILURE;
    }
    uv_fs_req_cleanup(&copy_req);

    file = fopen(hello_elf, "r");
    if (!file) {
        fprintf(stderr, "failed to open file %s: %s\n", hello_elf, strerror(errno));
        return EXIT_FAILURE;
    }

    elf = elf_begin(fileno(file), ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "get elf file failed: %s\n", elf_errmsg(-1));
        fclose(file);
        return EXIT_FAILURE;
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        fprintf(stderr, "file %s is not an ELF file\n", hello_elf);
        elf_end(elf);
        fclose(file);
        return EXIT_FAILURE;
    }

    char *hash = NULL;
    size_t hashSize = 0;
    if (welf_compute_elf_hash(elf, &hash, &hashSize) < 0) {
        fprintf(stderr, "compute_elf_hash failed: %s\n", welf_errmsg());
        elf_end(elf);
        fclose(file);
        return EXIT_FAILURE;
    }
    free(hash);

    unsigned char signature[] = "signature data";
    if (welf_save_elf_signature_via_objcopy(elf, signature, sizeof(signature), hello_elf) < 0) {
        fprintf(stderr, "save_elf_signature_via_objcopy failed: %s\n", welf_errmsg());
        return EXIT_FAILURE;
    }

    elf_end(elf);
    fclose(file);

    file = fopen(hello_elf, "r");
    if (!file) {
        fprintf(stderr, "failed to reopen file %s: %s\n", hello_elf, strerror(errno));
        return EXIT_FAILURE;
    }

    elf = elf_begin(fileno(file), ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "get elf file failed: %s\n", elf_errmsg(-1));
        fclose(file);
        return EXIT_FAILURE;
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        fprintf(stderr, "file %s is not an ELF file\n", hello_elf);
        elf_end(elf);
        fclose(file);
        return EXIT_FAILURE;
    }

    size_t retrievedSigLen = 0;
    unsigned char *retrievedSig = NULL;
    if (welf_get_elf_signature(elf, &retrievedSig, &retrievedSigLen) < 0) {
        fprintf(stderr, "get_elf_signature failed: %s\n", welf_errmsg());
        elf_end(elf);
        fclose(file);
        return EXIT_FAILURE;
    } else if (!retrievedSig) {
        fprintf(stderr, "get_elf_signature returned NULL\n");
        elf_end(elf);
        fclose(file);
        return EXIT_FAILURE;
    }

    if (retrievedSigLen != sizeof(signature) || memcmp(signature, retrievedSig, retrievedSigLen) != 0) {
        fprintf(stderr, "get_elf_signature returned wrong data\n");
        free(retrievedSig);
        elf_end(elf);
        fclose(file);
        return EXIT_FAILURE;
    }

    free(retrievedSig);
    elf_end(elf);
    fclose(file);
    printf("Tests succeeded");

    return EXIT_SUCCESS;
}
