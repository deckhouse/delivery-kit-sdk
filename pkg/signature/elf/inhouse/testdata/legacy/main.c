#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include "welf_elf.h"
#include "welf_error.h"

int main(int argc, char **argv) {
    if (argc < 3 || elf_version(EV_CURRENT) == EV_NONE) return 2;
    FILE *input = fopen(argv[2], "rb");
    if (!input) return 3;
    Elf *elf = elf_begin(fileno(input), ELF_C_READ, NULL);
    if (!elf) { fclose(input); return 4; }
    int result = 0;
    void *data = NULL;
    size_t size = 0;
    if (strcmp(argv[1], "hash") == 0) {
        result = welf_compute_elf_hash(elf, (char **)&data, &size);
    } else if (strcmp(argv[1], "extract") == 0) {
        result = welf_get_elf_signature(elf, (unsigned char **)&data, &size);
    } else if (strcmp(argv[1], "embed") == 0 && argc == 4) {
        FILE *payload = fopen(argv[3], "rb");
        if (!payload || fseek(payload, 0, SEEK_END) != 0) return 5;
        long length = ftell(payload);
        if (length < 0 || fseek(payload, 0, SEEK_SET) != 0) return 6;
        data = malloc((size_t)length);
        if (!data || fread(data, 1, (size_t)length, payload) != (size_t)length) return 7;
        if (fclose(payload) != 0) return 8;
        result = welf_save_elf_signature_via_objcopy(elf, data, (size_t)length, argv[2]);
    } else { result = -1; }
    if (result < 0) fprintf(stderr, "%s\n", welf_errmsg());
    if (result == 0 && size && fwrite(data, 1, size, stdout) != size) result = -1;
    free(data);
    elf_end(elf);
    if (fclose(input) != 0) result = -1;
    return result < 0 ? 1 : 0;
}
