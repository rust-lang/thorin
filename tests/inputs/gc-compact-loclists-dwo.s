# .dwo file for gc-compact-loclists.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children, DW_AT_loclists_base)
#     subprogram "dead_func1" (addrx 0, tombstoned, has children)
#       variable "w": DW_AT_location = loclistx 0 (dead)
#     subprogram "live_func" (addrx 1, live, has children)
#       variable "v": DW_AT_location = loclistx 1 (live)
#     subprogram "dead_func2" (addrx 2, tombstoned, has children)
#       variable "x": DW_AT_location = loclistx 2 (dead)
#
# .debug_loclists.dwo has 3 location lists in the offset table.
# After GC, dead_func1 and dead_func2 are removed, so only loclistx 1
# survives. The offset table should be compacted from 3 entries to 1,
# and the surviving variable's loclistx must be renumbered from 1 to 0.
#
# DWO ID is 0xbb.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xbb                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children, DW_AT_loclists_base)
	.byte	1
	.long	.Lloclists_table_base-.Lloclists_section_start # DW_AT_loclists_base

	# Abbrev 2: DW_TAG_subprogram "dead_func1" (addrx 0, tombstoned, has children)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0
	.asciz	"dead_func1"                    # DW_AT_name

	# Abbrev 3: DW_TAG_variable "w" (DW_AT_location = loclistx 0)
	.byte	3
	.byte	0                               # DW_AT_location: loclistx index 0

	.byte	0                               # End of dead_func1 children

	# Abbrev 2: DW_TAG_subprogram "live_func" (addrx 1, live, has children)
	.byte	2
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.asciz	"live_func"                     # DW_AT_name

	# Abbrev 3: DW_TAG_variable "v" (DW_AT_location = loclistx 1)
	.byte	3
	.byte	1                               # DW_AT_location: loclistx index 1

	.byte	0                               # End of live_func children

	# Abbrev 2: DW_TAG_subprogram "dead_func2" (addrx 2, tombstoned, has children)
	.byte	2
	.byte	2                               # DW_AT_low_pc: addrx index 2
	.asciz	"dead_func2"                    # DW_AT_name

	# Abbrev 3: DW_TAG_variable "x" (DW_AT_location = loclistx 2)
	.byte	3
	.byte	2                               # DW_AT_location: loclistx index 2

	.byte	0                               # End of dead_func2 children

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_loclists.dwo,"e",@progbits
.Lloclists_section_start:
	.long	.Lloclists_end-.Lloclists_start # Unit length
.Lloclists_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
	.long	3                               # Offset entry count
.Lloclists_table_base:
	# Offset table (3 entries, DWARF32 -> 4 bytes each)
	.long	.Lloclist0-.Lloclists_table_base    # Offset of location list 0
	.long	.Lloclist1-.Lloclists_table_base    # Offset of location list 1
	.long	.Lloclist2-.Lloclists_table_base    # Offset of location list 2
.Lloclist0:
	# Location list 0 (w in dead_func1): DW_LLE_default_location with DW_OP_reg0
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x50                            # DW_OP_reg0
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclist1:
	# Location list 1 (v in live_func): DW_LLE_default_location with DW_OP_reg1
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x51                            # DW_OP_reg1
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclist2:
	# Location list 2 (x in dead_func2): DW_LLE_default_location with DW_OP_reg2
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x52                            # DW_OP_reg2
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclists_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, DW_AT_loclists_base(sec_offset)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0x8c, 0x01                      # DW_AT_loclists_base (ULEB128: 140)
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, has children, DW_AT_low_pc(addrx) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_variable, no children, DW_AT_location(loclistx)
	.byte	3                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	0x22                            # DW_FORM_loclistx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
