# RUN: llvm-mc -triple x86_64-unknown-linux %s -filetype=obj -o %t.dwp
# RUN: not thorin %t.dwp -o %t 2>&1 | FileCheck %s

# CHECK: Error: Failed to add `{{.*}}/wrong-unit-type-info-v4.s.tmp.dwp` to DWARF package
# CHECK:  0: Failed to parse unit
# CHECK:  1: Hit the end of input before it was expected

  .section	.debug_info.dwo,"e",@progbits
  .long	.Ldebug_info_dwo_end0-.Ldebug_info_dwo_start0 # Length of Unit
.Ldebug_info_dwo_start0:
  .short	4                               # DWARF version number
  .long	0                               # Offset Into Abbrev. Section
  .byte	8                               # Address Size (in bytes)
  .byte	1                               # Abbrev [1] 0xb:0x1 DW_TAG_string_type
.Ldebug_info_dwo_end0:
  .section	.debug_abbrev.dwo,"e",@progbits
  .byte	1                               # Abbreviation Code
  .byte	18                              # DW_TAG_string_type
