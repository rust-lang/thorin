# Fake executable for gc-typed-expr.test
#
# Contains:
#   .debug_info:   DWARF5 skeleton CU (DW_UT_skeleton) with DWO ID 0x77,
#                  DW_AT_addr_base, and DW_AT_dwo_name
#   .debug_addr:   Three 8-byte addresses:
#                    index 0: 0xffffffffffffffff (tombstone for dead_func)
#                    index 1: 0x1000             (live for conv_func)
#                    index 2: 0x2000             (live for ct_func)
#   .debug_abbrev: abbreviation table for the skeleton CU

	.section	.debug_info,"",@progbits
	.long	.Ldebug_info_end-.Ldebug_info_start # Length of Unit
.Ldebug_info_start:
	.short	5                               # DWARF version number
	.byte	4                               # DW_UT_skeleton
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x77                            # DWO ID

	# [0x14] Abbrev 1: DW_TAG_compile_unit
	.byte	1
	.long	.Laddr_table_base               # DW_AT_addr_base
	.asciz	"DWO_PATH"                      # DW_AT_dwo_name (substituted by sed)
.Ldebug_info_end:

	.section	.debug_abbrev,"",@progbits
	# Abbrev 1: DW_TAG_compile_unit, no children
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	0                               # DW_CHILDREN_no
	.byte	115                             # DW_AT_addr_base
	.byte	23                              # DW_FORM_sec_offset
	.byte	118                             # DW_AT_dwo_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	0                               # End of abbreviations

	.section	.debug_addr,"",@progbits
	# DWARF5 .debug_addr header
	.long	.Laddr_end-.Laddr_start         # Length
.Laddr_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
.Laddr_table_base:
	# Address table entries (DW_AT_addr_base points here)
	.quad	0xffffffffffffffff              # Index 0: tombstone (dead_func)
	.quad	0x1000                          # Index 1: live address (conv_func)
	.quad	0x2000                          # Index 2: live address (ct_func)
.Laddr_end:
