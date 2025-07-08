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

    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        welf_set_errmsg("compute_elf_hash: failed to get ELF header for phnum: %s", elf_errmsg(-1));
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    size_t phnum = ehdr.e_phnum;
    for (size_t i = 0; i < phnum; ++i) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) == NULL) {
            welf_set_errmsg("compute_elf_hash: failed to get program header %zu: %s", i, elf_errmsg(-1));
            EVP_MD_CTX_free(ctx);
            return -1;
        }

        GElf_Phdr phdr_for_hash = phdr;
        phdr_for_hash.p_offset = 0;
        phdr_for_hash.p_vaddr = 0;
        phdr_for_hash.p_paddr = 0;
        phdr_for_hash.p_filesz = 0;
        phdr_for_hash.p_memsz = 0;
        phdr_for_hash.p_align = 0;

        if (EVP_DigestUpdate(ctx, &phdr_for_hash, sizeof(GElf_Phdr)) != 1) {
            welf_set_errmsg("compute_elf_hash: EVP_DigestUpdate failed for program header struct %zu: %s", i,
                            ERR_error_string(ERR_get_error(), NULL));
            EVP_MD_CTX_free(ctx);
            return -1;
        }
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
        if (strcmp(section_name, "signature") == 0) continue; // bsign
        if (strcmp(section_name, ".shstrtab") == 0) continue; // section names

        GElf_Shdr section_header_for_hash = section_header;
        section_header_for_hash.sh_addr = 0;
        section_header_for_hash.sh_offset = 0;
        section_header_for_hash.sh_size = 0;
        section_header_for_hash.sh_entsize = 0;
        section_header_for_hash.sh_link = 0;
        section_header_for_hash.sh_addralign = 0;
        section_header_for_hash.sh_info = 0;
        if (EVP_DigestUpdate(ctx, &section_header_for_hash, sizeof(GElf_Shdr)) != 1) {
            welf_set_errmsg("compute_elf_hash: EVP_DigestUpdate failed for section header %s: %s", section_name,
                            ERR_error_string(ERR_get_error(), NULL));
            EVP_MD_CTX_free(ctx);
            return -1;
        }

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

int welf_save_elf_signature_via_objcopy(Elf *elf, const void *data, size_t data_size, const char *elf_path) {
    uint8_t *noteBuf = NULL;
    size_t noteSize = 0;
    if (create_elf_note(WERF_SIGNATURE_NOTE_NAME, data, data_size, WERF_SIGNATURE_NOTE_TYPE, &noteBuf, &noteSize) < 0) {
        welf_set_errmsg("save_elf_signature_via_objcopy: failed to create ELF note: %s", welf_errmsg());
        return -1;
    }

    char tmp_elf_note_data[] = "/tmp/elfnote-data-XXXXXX";
    char tmp_elf_cleaned[] = "/tmp/elfnote-elf-cleaned-XXXXXX";
    char tmp_elf_final[] = "/tmp/elfnote-elf-final-XXXXXX";

    int fd_data = mkstemp(tmp_elf_note_data);
    if (fd_data == -1) {
        welf_set_errmsg("save_elf_signature_via_objcopy: mkstemp (data) failed: %s", strerror(errno));
        free(noteBuf);
        return -1;
    }

    ssize_t written = write(fd_data, noteBuf, noteSize);
    free(noteBuf);
    close(fd_data);
    if (written != (ssize_t) noteSize) {
        welf_set_errmsg("save_elf_signature_via_objcopy: failed to write all note data to temp file: %s",
                        strerror(errno));
        unlink(tmp_elf_note_data);
        return -1;
    }

    int fd_elf_final = mkstemp(tmp_elf_final);
    if (fd_elf_final == -1) {
        welf_set_errmsg("save_elf_signature_via_objcopy: mkstemp (elf final) failed: %s", strerror(errno));
        unlink(tmp_elf_note_data);
        return -1;
    }
    close(fd_elf_final);

    int has_signature_section = 0;
    size_t str_table_index;

    if (elf_getshdrstrndx(elf, &str_table_index) == 0) {
        Elf_Scn *section = NULL;
        GElf_Shdr section_header;

        while ((section = elf_nextscn(elf, section)) != NULL) {
            if (gelf_getshdr(section, &section_header) != &section_header) continue;

            char *section_name = elf_strptr(elf, str_table_index, section_header.sh_name);
            if (section_name && strcmp(section_name, WERF_SIGNATURE_SECTION_NAME) == 0) {
                has_signature_section = 1;
                break;
            }
        }
    }

    char errbuf[4096] = "";
    char add_section_cmd[1024];
    if (has_signature_section) {
        int fd_elf_cleaned = mkstemp(tmp_elf_cleaned);
        if (fd_elf_cleaned == -1) {
            welf_set_errmsg("save_elf_signature_via_objcopy: mkstemp (elf cleaned) failed: %s", strerror(errno));
            unlink(tmp_elf_note_data);
            unlink(tmp_elf_final);
            return -1;
        }
        close(fd_elf_cleaned);

        char rm_section_cmd[1024];
        snprintf(rm_section_cmd, sizeof(rm_section_cmd),
                 "objcopy --remove-section %s '%s' '%s' 2>&1",
                 WERF_SIGNATURE_SECTION_NAME, elf_path, tmp_elf_cleaned);
        FILE *rm_fp = popen(rm_section_cmd, "r");
        if (!rm_fp) {
            unlink(tmp_elf_note_data);
            unlink(tmp_elf_cleaned);
            unlink(tmp_elf_final);
            welf_set_errmsg("save_elf_signature_via_objcopy: popen failed for objcopy remove-section: %s",
                            strerror(errno));
            return -1;
        }

        fread(errbuf, 1, sizeof(errbuf) - 1, rm_fp);
        int ret = pclose(rm_fp);
        if (ret != 0) {
            unlink(tmp_elf_note_data);
            unlink(tmp_elf_cleaned);
            unlink(tmp_elf_final);
            welf_set_errmsg("save_elf_signature_via_objcopy: objcopy remove-section failed with code %d. Output: %s",
                            WEXITSTATUS(ret), errbuf);
            return -1;
        }

        snprintf(add_section_cmd, sizeof(add_section_cmd),
                 "objcopy --add-section %s=%s --set-section-flags %s=n '%s' '%s' 2>&1",
                 WERF_SIGNATURE_SECTION_NAME, tmp_elf_note_data,
                 WERF_SIGNATURE_SECTION_NAME, tmp_elf_cleaned, tmp_elf_final);
    } else {
        snprintf(add_section_cmd, sizeof(add_section_cmd),
                 "objcopy --add-section %s=%s --set-section-flags %s=n '%s' '%s' 2>&1",
                 WERF_SIGNATURE_SECTION_NAME, tmp_elf_note_data,
                 WERF_SIGNATURE_SECTION_NAME, elf_path, tmp_elf_final);
    }

    FILE *add_fp = popen(add_section_cmd, "r");
    if (!add_fp) {
        unlink(tmp_elf_note_data);
        if (has_signature_section) unlink(tmp_elf_cleaned);
        unlink(tmp_elf_final);
        welf_set_errmsg("save_elf_signature_via_objcopy: popen failed for objcopy add-section: %s", strerror(errno));
        return -1;
    }

    memset(errbuf, 0, sizeof(errbuf));
    fread(errbuf, 1, sizeof(errbuf) - 1, add_fp);
    int ret = pclose(add_fp);
    unlink(tmp_elf_note_data);
    if (has_signature_section) unlink(tmp_elf_cleaned);
    if (ret != 0) {
        unlink(tmp_elf_final);
        welf_set_errmsg("save_elf_signature_via_objcopy: objcopy failed with code %d. Output: %s", WEXITSTATUS(ret), errbuf);
        return -1;
    }

    char cp_cmd[1024];
    snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s' '%s' 2>&1", tmp_elf_final, elf_path);
    FILE *cp_fp = popen(cp_cmd, "r");
    if (!cp_fp) {
        unlink(tmp_elf_final);
        welf_set_errmsg("save_elf_signature_via_objcopy: popen failed for cp: %s", strerror(errno));
        return -1;
    }

    memset(errbuf, 0, sizeof(errbuf));
    fread(errbuf, 1, sizeof(errbuf) - 1, cp_fp);
    ret = pclose(cp_fp);
    unlink(tmp_elf_final);
    if (ret != 0) {
        welf_set_errmsg("save_elf_signature_via_objcopy: cp failed with code %d. Output: %s", WEXITSTATUS(ret), errbuf);
        return -1;
    }

    return 0;
}
