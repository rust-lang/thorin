# .dwo file for gc-loclist.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram "dead_func": DW_AT_low_pc = addrx 0 (tombstoned -> dead)
#     subprogram "live_func": DW_AT_low_pc = addrx 1 (live), has children
#       variable "v": DW_AT_location = loclistx 0 -> loclist in .debug_loclists.dwo
#     subprogram "target": DW_AT_low_pc = addrx 2 (tombstoned, kept alive by
#                           DW_OP_call4 in the location list expression)
#
# The location list in .debug_loclists.dwo contains a DW_LLE_default_location
# entry whose expression is { DW_OP_call4 <target CU-relative offset> }.
#
# DWO ID is 0xcc.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xcc                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children, DW_AT_loclists_base)
	.byte	1
	.long	.Lloclists_table_base-.Lloclists_section_start # DW_AT_loclists_base

	# Abbrev 2: DW_TAG_subprogram "dead_func" (addrx 0, tombstoned -> dead)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0
	.asciz	"dead_func"                     # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "live_func" (addrx 1, live, has children)
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.asciz	"live_func"                     # DW_AT_name

	# Abbrev 4: DW_TAG_variable "v" (DW_AT_location = loclistx 0)
	.byte	4
	.byte	0                               # DW_AT_location: loclistx index 0

	# End of live_func children
	.byte	0

	# Abbrev 2: DW_TAG_subprogram "target" (addrx 2, tombstoned, kept alive by loclist ref)
.Ltarget:
	.byte	2
	.byte	2                               # DW_AT_low_pc: addrx index 2
	.asciz	"target"                        # DW_AT_name

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_loclists.dwo,"e",@progbits
.Lloclists_section_start:
	# DWARF5 .debug_loclists header
	.long	.Lloclist_end-.Lloclist_start    # Unit length
.Lloclist_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
	.long	1                               # Offset entry count
.Lloclists_table_base:
	.long	.Lloclist0-.Lloclists_table_base # Offset of location list 0
.Lloclist0:
	# DW_LLE_default_location
	.byte	0x05                            # DW_LLE_default_location
	.byte	5                               # Expression length (ULEB128)
        # NB: It obviously doesn't make any real sense to DW_OP_call4 a
        # DW_TAG_subprogram. The point here is just to test the mark-and-sweep
        # of the DIEs.
	.byte	0x99                            # DW_OP_call4
	.long	.Ltarget-.Ldebug_info_dwo_start+4 # 4-byte CU-relative offset of target
	# DW_LLE_end_of_list
	.byte	0x00
.Lloclist_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, DW_AT_loclists_base(sec_offset)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0x8c, 0x01                      # DW_AT_loclists_base (ULEB128: 140)
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, has children, DW_AT_low_pc(addrx) + DW_AT_name(string)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_variable, no children, DW_AT_location(loclistx)
	.byte	4                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	0x22                            # DW_FORM_loclistx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
