# .dwo file for gc-ranges-dead.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children, DW_AT_rnglists_base)
#     subprogram "dead_func": DW_AT_ranges = rnglistx 0 (all entries tombstoned via startx_length)
#     subprogram "dead_base_func": DW_AT_ranges = rnglistx 1 (all entries tombstoned via base_addressx + offset_pair)
#     subprogram "mixed_func": DW_AT_ranges = rnglistx 2 (mix of tombstoned and live entries)
#     subprogram "live_func": DW_AT_low_pc = addrx 1 (live)
#
# .debug_rnglists.dwo contains three range lists:
#   index 0: single DW_RLE_startx_length referencing addrx 0 (tombstoned)
#   index 1: DW_RLE_base_addressx(addrx 2, tombstoned) + DW_RLE_offset_pair
#   index 2: DW_RLE_startx_length(addrx 0, tombstoned) + DW_RLE_startx_length(addrx 3, live)
#
# DWO ID is 0xdd.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xdd                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children, DW_AT_rnglists_base)
	.byte	1
	.long	.Lrnglists_table_base-.Lrnglists_section_start # DW_AT_rnglists_base

	# Abbrev 2: DW_TAG_subprogram "dead_func" (DW_AT_ranges = rnglistx 0)
	.byte	2
	.byte	0                               # DW_AT_ranges: rnglistx index 0
	.asciz	"dead_func"                     # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "dead_base_func" (DW_AT_ranges = rnglistx 1)
	.byte	2
	.byte	1                               # DW_AT_ranges: rnglistx index 1
	.asciz	"dead_base_func"                # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "mixed_func" (DW_AT_ranges = rnglistx 2)
	.byte	2
	.byte	2                               # DW_AT_ranges: rnglistx index 2
	.asciz	"mixed_func"                    # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "live_func" (DW_AT_low_pc = addrx 1)
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.asciz	"live_func"                     # DW_AT_name

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
	# Offsets are relative to the start of the offset table (= DW_AT_rnglists_base).
	.long	.Lrangelist0-.Lrnglists_table_base  # Offset of range list 0
	.long	.Lrangelist1-.Lrnglists_table_base  # Offset of range list 1
	.long	.Lrangelist2-.Lrnglists_table_base  # Offset of range list 2
.Lrangelist0:
	# DW_RLE_startx_length: addrx 0 (tombstoned), length 0x10
	.byte	0x03                            # DW_RLE_startx_length
	.byte	0                               # Start address index (ULEB128): addrx 0
	.byte	0x10                            # Length (ULEB128): 16 bytes
	# DW_RLE_end_of_list
	.byte	0x00
.Lrangelist1:
	# DW_RLE_base_addressx: addrx 2 (tombstoned)
	.byte	0x01                            # DW_RLE_base_addressx
	.byte	2                               # Address index (ULEB128): addrx 2
	# DW_RLE_offset_pair: offset 0, length 0x20
	.byte	0x04                            # DW_RLE_offset_pair
	.byte	0                               # Start offset (ULEB128)
	.byte	0x20                            # End offset (ULEB128)
	# DW_RLE_end_of_list
	.byte	0x00
.Lrangelist2:
	# DW_RLE_startx_length: addrx 0 (tombstoned), length 0x10
	.byte	0x03                            # DW_RLE_startx_length
	.byte	0                               # Start address index (ULEB128): addrx 0
	.byte	0x10                            # Length (ULEB128): 16 bytes
	# DW_RLE_startx_length: addrx 3 (live), length 0x10
	.byte	0x03                            # DW_RLE_startx_length
	.byte	3                               # Start address index (ULEB128): addrx 3
	.byte	0x10                            # Length (ULEB128): 16 bytes
	# DW_RLE_end_of_list
	.byte	0x00
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

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_name(string)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
