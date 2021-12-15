# RUN: llvm-mc -triple x86_64-unknown-linux %s -filetype=obj -o %t.o \
# RUN:         -split-dwarf-file=%t.dwo -dwarf-version=5
# RUN: not thorin %t.dwo -o %t.dwp 2>&1 | FileCheck %s

# CHECK: Error: Failed to add `{{.*}}/invalid-cu-header-version.s.tmp.dwo` to DWARF package
# CHECK:  0: Failed to parse unit header
# CHECK:  1: Hit the end of input before it was expected

    .section	.debug_info.dwo,"e",@progbits
    .long	0 # Length of Unit
