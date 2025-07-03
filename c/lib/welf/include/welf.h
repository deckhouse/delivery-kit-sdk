#ifndef WELF_H
#define WELF_H

char *compute_elf_hash(Elf *elf);

int get_elf_signature(Elf *elf, unsigned char **outBuf, size_t *outSize);

// int save_elf_signature(Elf *elf, size_t strTableIndex, const void *data, size_t dataSize);

int save_elf_signature_via_objcopy(const void *data, size_t data_size, const char *elf_path);

#endif
