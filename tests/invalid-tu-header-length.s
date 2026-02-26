# RUN: llvm-mc -triple x86_64-unknown-linux %s -filetype=obj -o %t.o -split-dwarf-file=%t.dwo \
# RUN:   -dwarf-version=5
# RUN: not thorin %t.dwo -o %t.dwp 2>&1 | FileCheck %s

# CHECK: Error: Failed to add `{{.*}}/invalid-tu-header-length.s.tmp.dwo` to DWARF package
# CHECK:  0: Failed to parse unit header
# CHECK:  1: unexpected end of input

    .section	.debug_info.dwo,"e",@progbits
    .long	.Ldebug_info_dwo_end0-.Ldebug_info_dwo_start0 # Length of Unit
.Ldebug_info_dwo_start0:
    .short	5                               # DWARF version number
    .byte	6                               # DWARF Unit Type (DW_UT_split_type)
    .byte	8                               # Address Size (in bytes)
    .long	0                               # Offset Into Abbrev. Section
    .quad	5657452045627120676             # Type Signature
.Ldebug_info_dwo_end0:
