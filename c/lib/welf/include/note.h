#ifndef NOTE_H
#define NOTE_H

int create_elf_note(const char *noteName, const void *noteDesc, uint32_t noteDescSize, uint32_t noteType, uint8_t **outBuf, size_t *outSize);

int parse_elf_note(const Elf_Data *noteData, const char **noteNamePtr, uint32_t *noteDescSize, uint32_t *noteType, const uint8_t **noteDescPtr);

#endif