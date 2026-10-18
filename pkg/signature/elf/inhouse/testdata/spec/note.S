.text
.byte 0
.globl spec_group
.set spec_group, 1
#ifdef GROUPED
.section .note.delivery-kit.signature,"Gw",%note,spec_group,comdat
#else
.section .note.delivery-kit.signature,"w",%note
#endif
.balign 4
.long 3, 4, 7
.asciz "PI"
.balign 4
.long 42
