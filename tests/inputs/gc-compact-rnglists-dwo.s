# .dwo file for gc-compact-rnglists.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children, DW_AT_rnglists_base)
#     subprogram "dead_func1": DW_AT_ranges = rnglistx 0 (tombstoned)
#     subprogram "live_func":  DW_AT_ranges = rnglistx 1 (live range)
#     subprogram "dead_func2": DW_AT_ranges = rnglistx 2 (tombstoned)
#
# .debug_rnglists.dwo has 3 range lists in the offset table.
# After GC, dead_func1 and dead_func2 are removed, so only rnglistx 1
# survives. The offset table should be compacted from 3 entries to 1,
# and the surviving subprogram's rnglistx must be renumbered from 1 to 0.
#
# DWO ID is 0xaa.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xaa                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children, DW_AT_rnglists_base)
	.byte	1
	.long	.Lrnglists_table_base-.Lrnglists_section_start # DW_AT_rnglists_base

	# Abbrev 2: DW_TAG_subprogram "dead_func1" (DW_AT_ranges = rnglistx 0)
	.byte	2
	.byte	0                               # DW_AT_ranges: rnglistx index 0
	.asciz	"dead_func1"                    # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "live_func" (DW_AT_ranges = rnglistx 1)
	.byte	2
	.byte	1                               # DW_AT_ranges: rnglistx index 1
	.asciz	"live_func"                     # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "dead_func2" (DW_AT_ranges = rnglistx 2)
	.byte	2
	.byte	2                               # DW_AT_ranges: rnglistx index 2
	.asciz	"dead_func2"                    # DW_AT_name

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_rnglists.dwo,"e",@progbits
.Lrnglists_section_start:
	.long	.Lrnglists_end-.Lrnglists_start # Unit length
.Lrnglists_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
	.long	3                               # Offset entry count
.Lrnglists_table_base:
	# Offset table (3 entries, DWARF32 -> 4 bytes each)
	.long	.Lrangelist0-.Lrnglists_table_base  # Offset of range list 0
	.long	.Lrangelist1-.Lrnglists_table_base  # Offset of range list 1
	.long	.Lrangelist2-.Lrnglists_table_base  # Offset of range list 2
.Lrangelist0:
	# Range list 0 (dead_func1): DW_RLE_startx_length addrx 0 (tombstoned), length 0x10
	.byte	0x03                            # DW_RLE_startx_length
	.byte	0                               # Start address index (ULEB128): addrx 0
	.byte	0x10                            # Length (ULEB128): 16 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrangelist1:
	# Range list 1 (live_func): DW_RLE_startx_length addrx 1 (live), length 0x20
	.byte	0x03                            # DW_RLE_startx_length
	.byte	1                               # Start address index (ULEB128): addrx 1
	.byte	0x20                            # Length (ULEB128): 32 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrangelist2:
	# Range list 2 (dead_func2): DW_RLE_startx_length addrx 2 (tombstoned), length 0x30
	.byte	0x03                            # DW_RLE_startx_length
	.byte	2                               # Start address index (ULEB128): addrx 2
	.byte	0x30                            # Length (ULEB128): 48 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrnglists_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, DW_AT_rnglists_base(sec_offset)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0x74                            # DW_AT_rnglists_base
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_ranges(rnglistx) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	0x55                            # DW_AT_ranges
	.byte	0x23                            # DW_FORM_rnglistx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
