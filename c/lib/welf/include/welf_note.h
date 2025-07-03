#ifndef WELF_NOTE_H
#define WELF_NOTE_H

int create_elf_note(const char *note_name, const void *note_desc, uint32_t note_desc_size, uint32_t note_type, uint8_t **out_buf, size_t *out_size);

int parse_elf_note(const Elf_Data *note_data, const char **note_name_ptr, uint32_t *note_desc_size, uint32_t *note_type, const uint8_t **note_desc_ptr);

#endif