# ELF signing

`Sign` and `Verify` keep their file-path APIs. ELF32 and ELF64, both byte orders,
and every `e_machine` value use the same implementation. Runtime signing and
verification require neither CGO nor an external executable. Section editing is
provided by `github.com/deckhouse/elfedit`, pinned to
`v0.0.0-20260907205808-d969ba637ddd` (the merge of PR #2). Its module requires Go 1.25, so the SDK now has the same minimum Go version.

## Signature contract

The signed message is the 64-character lowercase hexadecimal SHA-256 digest of:

1. Program headers in order, each represented as a 56-byte `GElf_Phdr` (ELF64
   layout), retaining only `p_type` and `p_flags`; all other fields are zero.
2. Sections in table order, starting at index 1. Skip sections named
   `.note.delivery-kit.signature`, `signature` (bsign), `.shstrtab`, and every
   `SHT_NOBITS` section. For each remaining section, hash a 64-byte `GElf_Shdr`
   retaining only the numeric `sh_name`, `sh_type`, and `sh_flags`, followed by
   exactly `sh_size` raw on-disk bytes at `sh_offset`. Compressed section bytes
   are hashed as stored, without decompression.

Legacy C code hashed native host-memory structures, including for ELF32 or an
ELF whose byte order differs from the host. Signing retains that native order;
verification accepts both historical host orders. For extended program counts,
the legacy hash visits `e_phnum` (65535) entries, while validation checks the full
resolved table. Changing this would change existing signatures.

The digest is passed to the existing `signature.Sign` implementation. Key
loading, signing algorithm, JSON bundle, certificates, trust roots, and
cryptographic verification remain in the SDK's existing packages.

The bundle is a single note in `.note.delivery-kit.signature`, with owner
`delivery-kit.signature` including its terminating NUL, type `0x31415926`, and
4-byte-padded name and descriptor. New note headers use ELF byte order.
Verification also recognizes the old C writer's host-order note header in
opposite-endian ELF files. The old writer could produce these notes even though
its own libelf-based extractor could not read them.

The ELF header, gaps, overlays, section-table placement and most header fields
are not authenticated by this legacy contract. This migration does not change
that coverage. It does not promise whole-file integrity.

## Re-signing and file writes

`elfedit.WriteSection` streams from the open source into a distinct temporary
file in the destination directory. It preserves existing section indexes and
name offsets, so signing does not need the old objcopy retry. Before replacing
the original, the SDK rechecks the digest and stored bundle, preserves Unix UID/GID, applies Linux ACLs/xattrs, restores the final file mode,
checks the resulting metadata, syncs and closes the output, checks for a concurrent source replacement/change,
and uses rename. The bundle read-back is defense against an incorrectly behaving editor, in addition to the independently checked digest identity. Failed work removes the temporary file. Symlink paths resolve
to their target; the symlink itself remains intact.

Callers must provide a stable source and destination directory for the operation.
Non-regular inputs are rejected before opening them, including FIFOs. The final stat check detects ordinary concurrent writes; it is not an atomic
compare-and-swap against hostile directory writers. Replacement creates a new
inode: other hard links retain the old inode. On Linux, the SDK copies all xattrs
visible to the signing process, including POSIX access ACLs, capabilities and
SELinux labels, after content and ownership are finalized. The temporary file
remains owner-writable while attributes are copied, with access ACL applied last
and final mode restored afterwards; read-only source files need no write access. Extra inherited
attributes are removed; the resulting attributes and mode are read back and
checked. Any read, write, removal or validation error leaves the source intact.
Linux may hide privileged namespaces such as `trusted.*` from unprivileged
processes: preserving those requires the corresponding capabilities. Restoring
a non-default SELinux label also requires the applicable relabel permissions;
a denied label change fails without replacing the source. Metadata
must remain stable during signing, just like file contents.

`security.ima` and `security.evm` are rejected because their integrity data
cannot be copied to edited content/a new inode without separate integrity
re-signing. This SDK does not implement that operation. Other operating systems
still do not copy ACLs/xattrs.
Unlike the old in-place copy, atomic replacement requires permission to assign the
source UID/GID to the new inode. If the signer cannot preserve either, signing
fails and leaves the source intact, even for an otherwise writable ordinary file.
Use artifacts owned by the signing account and one of its groups, or grant the
signing process permission to preserve ownership; ownership is never silently changed.

Only ELF-header section-table fields change within the original byte range.
Program headers, section payloads, gaps and overlays stay byte-for-byte intact.
Loader tests account explicitly for those header fields, which can themselves
be inside a mapped segment. No GNU objcopy whole-output equality is required.

Replacing a section does **not** erase its previous payload or old tables.
Re-signing grows the file. Verification reads only the active section selected
by the current table, never scans old payloads for a signature.

## Resource budgets

Source file size is checked against every metadata and payload range. There is
no whole-artifact memory buffer or fixed artifact-size ceiling. Before allocating
metadata, the SDK bounds normalized section headers plus the section-name table
to 64 MiB; program-header count is separately bounded by 64 MiB / 56. Notes are
bounded to 16 MiB. These are accepted-input limits, not a promise that total heap
use stays below 64 MiB: parsers, decoded structures, temporary strings, bundles,
and the editor can hold multiple copies. Name classification compares only the fixed signature/exclusion names, without allocating or scanning arbitrarily long names per section. Hashing uses a 64 KiB buffer and checks
context cancellation between chunks.

`MaxOutputSize` is source size + 128 MiB + note size + 4096 bytes. This permits
copied names and new section headers within the metadata budget plus ordinary
alignment, while rejecting alignment-driven expansion. It bounds output only;
the independent metadata checks are essential because elfedit parses metadata
before enforcing its output limit. Very large metadata or padding is rejected
without replacing the input. A 600 MiB sparse-artifact test exercises streaming. Linux xattr snapshots have a
separate 64 MiB aggregate budget each; individual values and name lists use the
Linux 64 KiB limits. Three snapshots can coexist during final validation: up to 192 MiB of attribute
payload/name budgets, plus map and buffer overhead.

## Checks

```sh
task format
task build
task deps:install:golangci-lint
task lint
task test:unit
task test:e2e paths=./pkg/signature/elf/inhouse labelFilter=elf-large parallel=false
```

On Linux, with a C compiler, libelf development headers, OpenSSL development
headers, and multiarch GNU objcopy available:

```sh
task test:elf-legacy
```

`testdata/legacy` retains the original C hash/note/editor sources from SDK commit
`53a3247`, unchanged, solely as a compatibility oracle. A small CLI adapter calls
them. Tests pair the old C hash/extractor with the unchanged SDK bundle verifier,
and the old C hash/objcopy writer with the unchanged SDK bundle signer. They test
both directions, replacement, and all four ELF encodings. C and objcopy are
dependencies of this explicit compatibility check only.

Encoding tests include i386, x86_64, ARM, AArch64, PowerPC, PowerPC64, S390 and an
unknown machine value. These synthetic cases prove encoding and machine-field
independence, not execution on those architectures. The Linux unit test signs
and executes the host's `/bin/true`, reporting the actual host architecture.
