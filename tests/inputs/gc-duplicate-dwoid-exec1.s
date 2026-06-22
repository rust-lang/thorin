# Executable 1 for gc-duplicate-dwoid.test
#
# Skeleton CU with DWO ID 0xdd. Address table:
#   index 0: 0x1000 (live — func_a is here)
#   index 1: 0xffffffffffffffff (tombstone — func_b not in this binary)

	.section	.debug_info,"",@progbits
	.long	.Ldebug_info_end-.Ldebug_info_start # Length of Unit
.Ldebug_info_start:
	.short	5                               # DWARF version number
	.byte	4                               # DW_UT_skeleton
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xdd                            # DWO ID

	.byte	1                               # Abbrev 1: DW_TAG_compile_unit
	.long	.Laddr_table_base               # DW_AT_addr_base
	.asciz	"DWO_PATH"                      # DW_AT_dwo_name (substituted by sed)
.Ldebug_info_end:

	.section	.debug_abbrev,"",@progbits
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
	.long	.Laddr_end-.Laddr_start         # Length
.Laddr_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
.Laddr_table_base:
	.quad	0x1000                          # Index 0: live (func_a)
	.quad	0xffffffffffffffff              # Index 1: tombstone (func_b)
.Laddr_end:
