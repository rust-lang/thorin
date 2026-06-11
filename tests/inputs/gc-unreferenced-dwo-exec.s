# Fake executable for gc-unreferenced-dwo.test
#
# Contains a skeleton CU with DWO ID 0xaa. This does NOT match the
# .dwo file's DWO ID (0xbb), so the .dwo's CU will hit the early
# return in maybe_gc (no executable data for that dwo_id).

	.section	.debug_info,"",@progbits
	.long	.Ldebug_info_end-.Ldebug_info_start # Length of Unit
.Ldebug_info_start:
	.short	5                               # DWARF version number
	.byte	4                               # DW_UT_skeleton
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xaa                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit
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
	.quad	0x1000                          # Index 0: some live address
.Laddr_end:
