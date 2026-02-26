# RUN: llvm-mc -triple x86_64-unknown-linux %s -filetype=obj -o %t.o \
# RUN:         -split-dwarf-file=%t.dwo -dwarf-version=5
# RUN: not thorin %t.dwo -o %t.dwp 2>&1 | FileCheck %s

# CHECK: Error: Failed to add `{{.*}}/invalid-cu-header-length.s.tmp.dwo` to DWARF package
# CHECK:  0: Failed to parse unit header
# CHECK:  1: unexpected end of input

    .section	.debug_info.dwo,"e",@progbits
    .long 16      # Length of Unit
    .short 5      # Version
