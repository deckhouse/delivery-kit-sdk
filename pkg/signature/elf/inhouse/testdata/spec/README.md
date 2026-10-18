# ELF specification fixtures

## Reproducible compiler inputs

Eight small `note-{plain,group}-<target>.elf` relocatable objects come from `note.S`.
The grouped note is a real COMDAT member; the plain note is not. Both carry
`SHF_WRITE`, allowing tests to prove that SDK replacement preserves only the
structural `SHF_GROUP` bit. The selected `.strtab` also supplies symbol names.

Regenerate from the SDK repository root (shell):

```sh
for target in i386-linux-gnu armeb-linux-gnueabi x86_64-linux-gnu aarch64_be-linux-gnu; do
  for kind in plain group; do
    define=
    if [ "$kind" = group ]; then define=-DGROUPED=1; fi
    clang -target "$target" $define -c pkg/signature/elf/inhouse/testdata/spec/note.S \
      -o "pkg/signature/elf/inhouse/testdata/spec/note-$kind-$target.elf"
    readelf -hSWgs "pkg/signature/elf/inhouse/testdata/spec/note-$kind-$target.elf"
  done
done
```

Provenance: Apple clang 21.0.0 (`clang-2100.1.1.101`). Regeneration with another
version may change bytes/order and needs structural review. Default `go test`
reads checked-in fixtures; no clang/binutils dependency is introduced.
AArch64 mapping symbols are expected and are not confused with the COMDAT symbol.
The four targets exercise ELF32/64 × LE/BE, not machine execution.

## Coverage map

References: [gABI sections](https://gabi.xinuos.com/elf/03-sheader.html),
[string tables](https://gabi.xinuos.com/elf/04-strtab.html),
[ELF header](https://gabi.xinuos.com/elf/02-eheader.html),
[program headers](https://gabi.xinuos.com/elf/07-pheader.html), and the extended
`e_phnum` convention in [elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html).
The ELF rules do not define the SDK's frozen legacy digest/exclusion policy.

| Case / clause | Fixture and tests | Expected behavior |
| --- | --- | --- |
| COMDAT and plain notes; §3.9 | Compiler objects; `ELF signature note groups` | Verify group symbol/index/order, original member list and flags; both signing APIs preserve only SHF_GROUP, produce identical bytes, verify, and repeat without another signing call or file replacement. |
| Shared, noncanonical, index-selected name tables; §4 | Existing `stringTableELF`, `preserved ELF string tables`; compiler fixtures | Preserve original table/header, symbols, numeric names and original digest. Existing unrelated `.shstrtab` is not selected merely by label. |
| Exact names/prefixes; §4 | Existing `ELF review regressions`; editor suffix tests | Preserve existing classification semantics; no prefix matching. |
| Empty selected table; §4 | Existing `ELF empty selected name table` | Accept logical empty name at zero; preserve original zero-size header and independently constructed original digest through both APIs. |
| Inactive PT_NULL/SHT_NULL; §§7.2, 3.3 | Existing `ELF inactive metadata compatibility` | Ignore PT_NULL geometry and inactive live-note aliases, but retain legacy header/payload hashing and name exclusions. Existing tests cover both host orders and inactive-only payload bytes. Physical-table protection is covered in editor tests. |
| Zero-size, NOBITS, compression; §§3.2, 3.3, 3.7 | New `ELF specification fixtures`, deterministic ABI-structure builders | Preserve complete source section headers and compressed raw bytes; independently decode compressed data, preserve original digest, sign via both APIs. |
| Extended section count/name index; §§2, 3.1 | Existing `Given a detached table crossing the reserved index boundary` | Build real-size threshold tables on demand; preserve source metadata and resolve extended indexes. |
| PN_XNUM boundary | New `Given canonical PN_XNUM boundaries`, counts 65535/65536 | Build full tables on demand; preserve resolved count and all program bytes. Independent digest construction uses exactly the frozen raw count 65535, not the resolved count. No small escaped counts are valid-input cases. |
| Unsupported name-table configurations; §§3.7, 4 | New `Given unsupported selected name-table configurations` | Exact errors for absent selected table / correctly encoded compressed selected table; nil byte output and unchanged file/input, with no temporary file left behind. |
| New dependent metadata; §§3.2–3.5 | Editor `metadata_test.go` and `testdata/spec` corpus | Explicit creation rejection does not affect ordinary SDK note creation or existing grouped-note replacement. |

These tests use independent active-header/group/symbol/payload assertions.
Successful parsing or readelf exit status alone is not an acceptance oracle.
Canonical mapped-name-table support remains deferred. Legacy digest formula,
exclusions, PN_XNUM behavior and note encoding are unchanged.
