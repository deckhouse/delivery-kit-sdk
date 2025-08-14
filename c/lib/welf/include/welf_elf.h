#ifndef WELF_ELF_H
#define WELF_ELF_H

int welf_compute_elf_hash(Elf *elf, char **result_buf, size_t *result_size);

int welf_get_elf_signature(Elf *elf, unsigned char **result_buf, size_t *result_size);

int welf_save_elf_signature_via_objcopy(Elf *elf, const void *data, size_t data_size, const char *elf_path);

#endif
