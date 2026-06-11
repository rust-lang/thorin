# .dwo file for gc-nothing-dead-orphan-list.test
#
# DWARF5 split-compile unit where all DIEs are live, but there is an
# orphan (unreferenced) range list at index 0 in .debug_rnglists.dwo
# and an orphan location list at index 0 in .debug_loclists.dwo.
#
# Compile unit (DW_UT_split_compile, DWO ID 0xbb):
#   compile_unit (children, DW_AT_rnglists_base, DW_AT_loclists_base)
#     subprogram "func_a" (rnglistx 1, loclistx 1, live)
#     subprogram "func_b" (rnglistx 2, loclistx 2, live)
#
# .debug_rnglists.dwo has 3 range lists (indices 0, 1, 2).
#   Index 0 is orphaned (not referenced by any DIE).
# .debug_loclists.dwo has 3 location lists (indices 0, 1, 2).
#   Index 0 is orphaned (not referenced by any DIE).
#
# Since all DIEs are live, GC should NOT rewrite debug_info, and
# must NOT compact the rnglists/loclists offset tables.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xbb                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.long	.Lrnglists_table_base-.Lrnglists_section_start # DW_AT_rnglists_base
	.long	.Lloclists_table_base-.Lloclists_section_start # DW_AT_loclists_base

	# Abbrev 2: DW_TAG_subprogram "func_a" (rnglistx 1, loclistx 1, live)
	.byte	2
	.byte	1                               # DW_AT_ranges: rnglistx index 1
	.byte	1                               # DW_AT_location: loclistx index 1
	.asciz	"func_a"                        # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "func_b" (rnglistx 2, loclistx 2, live)
	.byte	2
	.byte	2                               # DW_AT_ranges: rnglistx index 2
	.byte	2                               # DW_AT_location: loclistx index 2
	.asciz	"func_b"                        # DW_AT_name

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
	.long	.Lrangelist0-.Lrnglists_table_base  # Offset of range list 0
	.long	.Lrangelist1-.Lrnglists_table_base  # Offset of range list 1
	.long	.Lrangelist2-.Lrnglists_table_base  # Offset of range list 2
.Lrangelist0:
	# Range list 0 (orphan): DW_RLE_startx_length addrx 0, length 0x08
	.byte	0x03                            # DW_RLE_startx_length
	.byte	0                               # Start address index (ULEB128): addrx 0
	.byte	0x08                            # Length (ULEB128): 8 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrangelist1:
	# Range list 1 (func_a): DW_RLE_startx_length addrx 0, length 0x20
	.byte	0x03                            # DW_RLE_startx_length
	.byte	0                               # Start address index (ULEB128): addrx 0
	.byte	0x20                            # Length (ULEB128): 32 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrangelist2:
	# Range list 2 (func_b): DW_RLE_startx_length addrx 1, length 0x30
	.byte	0x03                            # DW_RLE_startx_length
	.byte	1                               # Start address index (ULEB128): addrx 1
	.byte	0x30                            # Length (ULEB128): 48 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrnglists_end:

	.section	.debug_loclists.dwo,"e",@progbits
.Lloclists_section_start:
	.long	.Lloclists_end-.Lloclists_start # Unit length
.Lloclists_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
	.long	3                               # Offset entry count
.Lloclists_table_base:
	.long	.Lloclist0-.Lloclists_table_base    # Offset of location list 0
	.long	.Lloclist1-.Lloclists_table_base    # Offset of location list 1
	.long	.Lloclist2-.Lloclists_table_base    # Offset of location list 2
.Lloclist0:
	# Location list 0 (orphan): DW_LLE_default_location with DW_OP_reg2
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x52                            # DW_OP_reg2
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclist1:
	# Location list 1 (func_a): DW_LLE_default_location with DW_OP_reg0
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x50                            # DW_OP_reg0
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclist2:
	# Location list 2 (func_b): DW_LLE_default_location with DW_OP_reg1
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x51                            # DW_OP_reg1
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclists_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children,
	#           DW_AT_rnglists_base(sec_offset) + DW_AT_loclists_base(sec_offset)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0x74                            # DW_AT_rnglists_base
	.byte	23                              # DW_FORM_sec_offset
	.byte	0x8c, 0x01                      # DW_AT_loclists_base (ULEB128: 140)
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children,
	#           DW_AT_ranges(rnglistx) + DW_AT_location(loclistx) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	0x55                            # DW_AT_ranges
	.byte	0x23                            # DW_FORM_rnglistx
	.byte	2                               # DW_AT_location
	.byte	0x22                            # DW_FORM_loclistx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
