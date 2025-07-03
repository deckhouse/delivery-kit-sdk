#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libelf.h"
#include "werror.h"

int create_elf_note(const char *noteName, const void *noteDesc, uint32_t noteDescSize, uint32_t noteType, uint8_t **outBuf, size_t *outSize) {
    if (!noteName) {
        welf_set_errmsg("create_elf_note: noteName is NULL");
        return -1;
    }

    if (!noteDesc && noteDescSize > 0) {
        welf_set_errmsg("create_elf_note: noteDesc is NULL but noteDescSize > 0");
        return -1;
    }

    if (!outBuf || !outSize) {
        welf_set_errmsg("create_elf_note: outBuf or outSize is NULL");
        return -1;
    }

    uint32_t nameSize = strlen(noteName) + 1;
    size_t namePadded = (nameSize + 3) & ~3;
    size_t descPadded = (noteDescSize + 3) & ~3;
    size_t total = 12 + namePadded + descPadded;

    uint8_t *buf = calloc(1, total);
    if (!buf) {
        welf_set_errmsg("create_elf_note: failed to allocate note buffer: %s", strerror(errno));
        return -1;
    }

    *(uint32_t *)(buf) = nameSize;
    *(uint32_t *)(buf + 4) = noteDescSize;
    *(uint32_t *)(buf + 8) = noteType;

    memcpy(buf + 12, noteName, nameSize);
    if (noteDesc && noteDescSize > 0) {
        memcpy(buf + 12 + namePadded, noteDesc, noteDescSize);
    }

    *outBuf = buf;
    *outSize = total;

    return 0;
}

int parse_elf_note(const Elf_Data *noteData, const char **noteNamePtr, uint32_t *noteDescSize, uint32_t *noteType, const uint8_t **noteDescPtr) {
    if (!noteData) {
        welf_set_errmsg("parse_elf_note: noteData is NULL");
        return -1;
    }

    if (!noteData->d_buf) {
        welf_set_errmsg("parse_elf_note: noteData buffer is NULL");
        return -1;
    }

    if (noteData->d_size < 12) {
        welf_set_errmsg("parse_elf_note: noteData size too small for ELF note header");
        return -1;
    }

    const uint8_t *buf = (const uint8_t *)noteData->d_buf;
    uint32_t nameSize = *(const uint32_t *)(buf);
    *noteDescSize = *(const uint32_t *)(buf + 4);
    *noteType = *(const uint32_t *)(buf + 8);

    if (nameSize == 0) {
        welf_set_errmsg("parse_elf_note: nameSize is zero");
        return -1;
    }

    // Allow zero-sized descriptors
    // if (*noteDescSize == 0) {
    //     welf_set_errmsg("parse_elf_note: noteDescSize is zero");
    //     return -1;
    // }

    size_t nameOffset = 12;
    size_t namePadded = (nameSize + 3) & ~3;
    size_t descOffset = nameOffset + namePadded;

    if (*noteDescSize > 0 && descOffset + *noteDescSize > noteData->d_size) {
        welf_set_errmsg("parse_elf_note: descriptor out of bounds");
        return -1;
    }

    *noteNamePtr = (const char *)(buf + nameOffset);
    *noteDescPtr = (*noteDescSize > 0) ? buf + descOffset : NULL;

    return 0;
}
