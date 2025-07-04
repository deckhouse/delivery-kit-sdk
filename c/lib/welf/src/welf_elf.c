#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#include "gelf.h"
#include "libelf.h"
#include "welf_error.h"
#include "welf_note.h"

#define WERF_SIGNATURE_SECTION_NAME ".note.werf.signature"
#define WERF_SIGNATURE_NOTE_NAME "werf.signature"
#define WERF_SIGNATURE_NOTE_TYPE 0x31415926

// static ssize_t get_or_create_section_name(Elf *elf, size_t strTableIndex, const char *name) {
//     Elf_Scn *shstrtabSection = elf_getscn(elf, strTableIndex);
//     if (!shstrtabSection) {
//         welf_set_errmsg("get_or_create_section_name: failed to get shstrtab section: %s", elf_errmsg(-1));
//         return -1;
//     }
//
//     Elf_Data *shstrtabData = elf_getdata(shstrtabSection, NULL);
//     if (!shstrtabData) {
//         welf_set_errmsg("get_or_create_section_name: failed to get shstrtab data: %s", elf_errmsg(-1));
//         return -1;
//     }
//
//     size_t shstrtabSize = shstrtabData->d_size;
//     char *shstrtab = (char *) shstrtabData->d_buf;
//     if (!shstrtab) {
//         welf_set_errmsg("get_or_create_section_name: shstrtab data buffer is NULL");
//         return -1;
//     }
//
//     // Search for the name in the current shstrtab
//     for (size_t i = 0; i + strlen(name) < shstrtabSize; ++i) {
//         if (strcmp(&shstrtab[i], name) == 0) {
//             return (ssize_t) i;
//         }
//     }
//
//     // Not found, append to shstrtab using malloc
//     size_t nameOffset = shstrtabSize;
//     size_t newSize = shstrtabSize + strlen(name) + 1;
//     char *newBuf = (char *)malloc(newSize);
//     if (!newBuf) {
//         welf_set_errmsg("get_or_create_section_name: failed to allocate memory for new section name: %s",
//                         strerror(errno));
//         return -1;
//     }
//     memcpy(newBuf, shstrtab, shstrtabSize);
//     strcpy(newBuf + shstrtabSize, name);
//     shstrtabData->d_buf = newBuf;
//     shstrtabData->d_size = newSize;
//     elf_flagdata(shstrtabData, ELF_C_SET, ELF_F_DIRTY);
//     elf_flagscn(shstrtabSection, ELF_C_SET, ELF_F_DIRTY);
//
//     // Update the section header's sh_size
//     GElf_Shdr shdr;
//     if (gelf_getshdr(shstrtabSection, &shdr) == NULL) {
//         welf_set_errmsg("get_or_create_section_name: failed to get shstrtab section header: %s", elf_errmsg(-1));
//         return -1;
//     }
//     shdr.sh_size = newSize;
//     if (gelf_update_shdr(shstrtabSection, &shdr) == 0) {
//         welf_set_errmsg("get_or_create_section_name: failed to update shstrtab section header: %s", elf_errmsg(-1));
//         return -1;
//     }
//
//     return (ssize_t) nameOffset;
// }

// FIXME: ignore bsign signature
// FIXME: add elf header, program headers, section headers, something other? to the hash
int welf_compute_elf_hash(Elf *elf, char **result_buf, size_t *result_size) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        welf_set_errmsg("compute_elf_hash: failed to create EVP_MD_CTX: %s", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        welf_set_errmsg("compute_elf_hash: EVP_DigestInit_ex failed: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    size_t str_table_index;
    if (elf_getshdrstrndx(elf, &str_table_index) != 0) {
        welf_set_errmsg("compute_elf_hash: get string table index failed: %s", elf_errmsg(-1));
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    Elf_Scn *section = NULL;
    GElf_Shdr section_header;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (gelf_getshdr(section, &section_header) != &section_header) {
            welf_set_errmsg("compute_elf_hash: failed to get section header: %s", elf_errmsg(-1));
            EVP_MD_CTX_free(ctx);
            return -1;
        }

        char *section_name = elf_strptr(elf, str_table_index, section_header.sh_name);
        if (!section_name) {
            welf_set_errmsg("compute_elf_hash: failed to get section name: %s", elf_errmsg(-1));
            EVP_MD_CTX_free(ctx);
            return -1;
        }

        if (strcmp(section_name, WERF_SIGNATURE_SECTION_NAME) == 0) continue;

        size_t section_size = section_header.sh_size;
        size_t section_offset = section_header.sh_offset;
        const size_t chunk_size = 4096;

        size_t cur_offset = 0;
        while (cur_offset < section_size) {
            size_t cur_chunk_size = (section_size - cur_offset > chunk_size) ? chunk_size : (section_size - cur_offset);

            Elf_Data *chunk = elf_getdata_rawchunk(elf, section_offset + cur_offset, cur_chunk_size, ELF_T_BYTE);
            if (!chunk) {
                welf_set_errmsg("compute_elf_hash: failed to get data chunk for section %s: %s", section_name,
                                elf_errmsg(-1));
                EVP_MD_CTX_free(ctx);
                return -1;
            }

            if (chunk->d_buf && chunk->d_size > 0) {
                if (EVP_DigestUpdate(ctx, chunk->d_buf, chunk->d_size) != 1) {
                    welf_set_errmsg("compute_elf_hash: EVP_DigestUpdate failed for section %s: %s", section_name,
                                    ERR_error_string(ERR_get_error(), NULL));
                    EVP_MD_CTX_free(ctx);
                    return -1;
                }
            }

            cur_offset += cur_chunk_size;
        }
    }

    if (EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        welf_set_errmsg("compute_elf_hash: EVP_DigestFinal_ex failed: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    char *hex_buf = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!hex_buf) {
        welf_set_errmsg("compute_elf_hash: failed to allocate memory for hex hash");
        return -1;
    }

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex_buf + i * 2, "%02x", hash[i]);
    hex_buf[SHA256_DIGEST_LENGTH * 2] = '\0';

    if (result_buf) *result_buf = hex_buf;
    if (result_size) *result_size = SHA256_DIGEST_LENGTH * 2;

    return 0;
}

int welf_get_elf_signature(Elf *elf, unsigned char **result_buf, size_t *result_size) {
    size_t str_table_index;
    if (elf_getshdrstrndx(elf, &str_table_index) != 0) {
        welf_set_errmsg("get_elf_signature: get string table index failed: %s", elf_errmsg(-1));
        return -1;
    }

    Elf_Scn *section = NULL;
    GElf_Shdr section_header;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (gelf_getshdr(section, &section_header) != &section_header) {
            welf_set_errmsg("get_elf_signature: failed to get section header: %s", elf_errmsg(-1));
            return -1;
        }

        char *section_name = elf_strptr(elf, str_table_index, section_header.sh_name);
        if (!section_name) {
            welf_set_errmsg("get_elf_signature: failed to get section name: %s", elf_errmsg(-1));
            return -1;
        }

        if (strcmp(section_name, WERF_SIGNATURE_SECTION_NAME) != 0) continue;

        Elf_Data *note_data = elf_getdata(section, NULL);
        if (!note_data) {
            welf_set_errmsg("get_elf_signature: failed to get data for section %s: %s", section_name, elf_errmsg(-1));
            return -1;
        }

        uint32_t note_desc_size, note_type;
        const char *note_name;
        const uint8_t *note_desc_ptr;
        if (parse_elf_note(note_data, &note_name, &note_desc_size, &note_type, &note_desc_ptr) < 0) {
            welf_set_errmsg("get_elf_signature: failed to parse note in section %s: %s", section_name, welf_errmsg());
            return -1;
        }
        if (note_type != WERF_SIGNATURE_NOTE_TYPE) {
            welf_set_errmsg("get_elf_signature: unexpected note type in section %s: expected %u, got %u",
                            section_name, WERF_SIGNATURE_NOTE_TYPE, note_type);
            return -1;
        }
        if (note_desc_size == 0) {
            return 0;
        }
        if (!note_desc_ptr) {
            welf_set_errmsg("get_elf_signature: null descriptor pointer for non-zero size in section %s", section_name);
            return -1;
        }

        unsigned char *result = malloc(note_desc_size);
        if (!result) {
            welf_set_errmsg("get_elf_signature: failed to allocate memory for desc: %s", strerror(errno));
            return -1;
        }

        memcpy(result, note_desc_ptr, note_desc_size);
        if (result_buf) *result_buf = result;
        if (result_size) *result_size = note_desc_size;

        return 0;
    }

    return 0;
}

// int save_elf_signature(Elf *elf, size_t strTableIndex, const void *data, size_t dataSize) {
//     Elf_Scn *section = NULL;
//     GElf_Shdr sectionHeader;
//
//     int signatureSectionFound = 0;
//     while ((section = elf_nextscn(elf, section)) != NULL) {
//         if (gelf_getshdr(section, &sectionHeader) != &sectionHeader) {
//             welf_set_errmsg("save_elf_signature: failed to retrieve section header: %s", elf_errmsg(-1));
//             return -1;
//         }
//
//         char *sectionName = elf_strptr(elf, strTableIndex, sectionHeader.sh_name);
//         if (!sectionName) {
//             welf_set_errmsg("save_elf_signature: failed to get section name: %s", elf_errmsg(-1));
//             return -1;
//         }
//
//         if (strcmp(sectionName, WERF_SIGNATURE_SECTION_NAME) == 0) {
//             signatureSectionFound = 1;
//             break;
//         }
//     }
//
//     if (!signatureSectionFound) {
//         section = elf_newscn(elf);
//         if (!section) {
//             welf_set_errmsg("save_elf_signature: failed to create new ELF section: %s", elf_errmsg(-1));
//             return -1;
//         }
//
//         ssize_t nameOffset = get_or_create_section_name(elf, strTableIndex, WERF_SIGNATURE_SECTION_NAME);
//         if (nameOffset < 0) {
//             welf_set_errmsg("save_elf_signature: failed to set section name: %s", welf_errmsg());
//             return -1;
//         }
//
//         memset(&sectionHeader, 0, sizeof(sectionHeader));
//
//         sectionHeader.sh_name = (size_t) nameOffset;
//         sectionHeader.sh_type = SHT_NOTE;
//         sectionHeader.sh_flags = 0;
//         sectionHeader.sh_entsize = 0;
//         sectionHeader.sh_addralign = 4;
//
//         if (gelf_update_shdr(section, &sectionHeader) <= 0) {
//             welf_set_errmsg("save_elf_signature: failed to update section header: %s", elf_errmsg(-1));
//             return -1;
//         }
//     } else {
//         // If we're reusing an existing section, make sure to remove any existing data
//         Elf_Data *oldData;
//         while ((oldData = elf_getdata(section, NULL)) != NULL) {
//             oldData->d_size = 0;
//             elf_flagdata(oldData, ELF_C_SET, ELF_F_DIRTY);
//         }
//     }
//
//     uint8_t *noteBuf = NULL;
//     size_t noteSize = 0;
//     if (create_elf_note(WERF_SIGNATURE_NOTE_NAME, data, dataSize, WERF_SIGNATURE_NOTE_TYPE, &noteBuf, &noteSize) < 0) {
//         welf_set_errmsg("save_elf_signature: failed to create ELF note: %s", welf_errmsg());
//         return -1;
//     }
//
//     Elf_Data *elfData = elf_newdata(section);
//     if (!elfData) {
//         welf_set_errmsg("save_elf_signature: failed to create new ELF data: %s", elf_errmsg(-1));
//         free(noteBuf);
//         return -1;
//     }
//
//     elfData->d_buf = noteBuf;
//     elfData->d_size = noteSize;
//     elfData->d_align = 4;
//     elfData->d_type = ELF_T_BYTE;
//     elfData->d_off = 0;
//     elfData->d_version = EV_CURRENT;
//
//     // Mark the data as dirty
//     elf_flagdata(elfData, ELF_C_SET, ELF_F_DIRTY);
//     // Mark the section as dirty
//     elf_flagscn(section, ELF_C_SET, ELF_F_DIRTY);
//
//     if (gelf_getshdr(section, &sectionHeader) != &sectionHeader) {
//         welf_set_errmsg("save_elf_signature: failed to get updated section header: %s", elf_errmsg(-1));
//         return -1;
//     }
//
//     sectionHeader.sh_size = noteSize;
//
//     if (gelf_update_shdr(section, &sectionHeader) <= 0) {
//         welf_set_errmsg("save_elf_signature: failed to update section header size: %s", elf_errmsg(-1));
//         return -1;
//     }
//
//     return 0;
// }

int welf_save_elf_signature_via_objcopy(const void *data, size_t data_size, const char *elf_path) {
    uint8_t *noteBuf = NULL;
    size_t noteSize = 0;
    if (create_elf_note(WERF_SIGNATURE_NOTE_NAME, data, data_size, WERF_SIGNATURE_NOTE_TYPE, &noteBuf, &noteSize) < 0) {
        welf_set_errmsg("save_elf_signature_via_objcopy: failed to create ELF note: %s", welf_errmsg());
        return -1;
    }

    char tmpdata[] = "/tmp/elfnote-data-XXXXXX";
    char tmpelf[] = "/tmp/elfnote-elf-XXXXXX";
    int fd_data = mkstemp(tmpdata);
    if (fd_data == -1) {
        welf_set_errmsg("save_elf_signature_via_objcopy: mkstemp (data) failed: %s", strerror(errno));
        free(noteBuf);
        return -1;
    }

    ssize_t written = write(fd_data, noteBuf, noteSize);
    free(noteBuf);
    if (written != (ssize_t)noteSize) {
        welf_set_errmsg("save_elf_signature_via_objcopy: failed to write all note data to temp file: %s", strerror(errno));
        close(fd_data);
        unlink(tmpdata);
        return -1;
    }
    close(fd_data);

    int fd_elf = mkstemp(tmpelf);
    if (fd_elf == -1) {
        welf_set_errmsg("save_elf_signature_via_objcopy: mkstemp (elf) failed: %s", strerror(errno));
        unlink(tmpdata);
        return -1;
    }
    close(fd_elf);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "objcopy --add-section %s=%s --set-section-flags %s=n %s %s",
        WERF_SIGNATURE_SECTION_NAME, tmpdata,
        WERF_SIGNATURE_SECTION_NAME, elf_path, tmpelf);

    int ret = system(cmd);
    unlink(tmpdata);
    if (ret != 0) {
        unlink(tmpelf);
        welf_set_errmsg("save_elf_signature_via_objcopy: objcopy failed with code %d", ret);
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", tmpelf, elf_path);
    ret = system(cmd);
    unlink(tmpelf);
    if (ret != 0) {
        welf_set_errmsg("save_elf_signature_via_objcopy: cp failed with code %d", ret);
        return -1;
    }

    return 0;
}
