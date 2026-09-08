#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libelf.h"
#include "welf_error.h"

int create_elf_note(const char *note_name, const void *note_desc, uint32_t note_desc_size, uint32_t note_type, uint8_t **out_buf, size_t *out_size) {
    if (!note_name) {
        welf_set_errmsg("create_elf_note: note_name is NULL");
        return -1;
    }

    if (!note_desc && note_desc_size > 0) {
        welf_set_errmsg("create_elf_note: note_desc is NULL but note_desc_size > 0");
        return -1;
    }

    if (!out_buf || !out_size) {
        welf_set_errmsg("create_elf_note: out_buf or out_size is NULL");
        return -1;
    }

    uint32_t name_size = strlen(note_name) + 1;
    size_t name_padded = (name_size + 3) & ~3;
    size_t desc_padded = (note_desc_size + 3) & ~3;
    size_t total = 12 + name_padded + desc_padded;

    uint8_t *buf = calloc(1, total);
    if (!buf) {
        welf_set_errmsg("create_elf_note: failed to allocate note buffer: %s", strerror(errno));
        return -1;
    }

    *(uint32_t *)(buf) = name_size;
    *(uint32_t *)(buf + 4) = note_desc_size;
    *(uint32_t *)(buf + 8) = note_type;

    memcpy(buf + 12, note_name, name_size);
    if (note_desc && note_desc_size > 0) {
        memcpy(buf + 12 + name_padded, note_desc, note_desc_size);
    }

    *out_buf = buf;
    *out_size = total;

    return 0;
}

int parse_elf_note(const Elf_Data *note_data, const char **note_name_ptr, uint32_t *note_desc_size, uint32_t *note_type, const uint8_t **note_desc_ptr) {
    if (!note_data) {
        welf_set_errmsg("parse_elf_note: note_data is NULL");
        return -1;
    }

    if (!note_data->d_buf) {
        welf_set_errmsg("parse_elf_note: note_data buffer is NULL");
        return -1;
    }

    if (note_data->d_size < 12) {
        welf_set_errmsg("parse_elf_note: note_data size too small for ELF note header");
        return -1;
    }

    const uint8_t *buf = (const uint8_t *)note_data->d_buf;
    uint32_t nameSize = *(const uint32_t *)(buf);
    *note_desc_size = *(const uint32_t *)(buf + 4);
    *note_type = *(const uint32_t *)(buf + 8);

    if (nameSize == 0) {
        welf_set_errmsg("parse_elf_note: nameSize is zero");
        return -1;
    }

    size_t nameOffset = 12;
    size_t namePadded = (nameSize + 3) & ~3;
    size_t descOffset = nameOffset + namePadded;

    if (*note_desc_size > 0 && descOffset + *note_desc_size > note_data->d_size) {
        welf_set_errmsg("parse_elf_note: descriptor out of bounds");
        return -1;
    }

    *note_name_ptr = (const char *)(buf + nameOffset);
    *note_desc_ptr = (*note_desc_size > 0) ? buf + descOffset : NULL;

    return 0;
}
