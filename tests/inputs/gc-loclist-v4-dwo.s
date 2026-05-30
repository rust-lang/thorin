# .dwo file for gc-loclist-v4.test
#
# DWARF4 split-compile unit (GNU extension) containing:
#   compile_unit (children, DW_AT_GNU_dwo_id = 0xdd)
#     subprogram "dead_func": DW_AT_low_pc = GNU_addr_index 0 (tombstoned -> dead)
#     subprogram "live_func": DW_AT_low_pc = GNU_addr_index 1 (live), has children
#       variable "v": DW_AT_location = sec_offset -> loclist in .debug_loc.dwo
#     subprogram "target": DW_AT_low_pc = GNU_addr_index 2 (tombstoned, kept alive by
#                           DW_OP_call4 in the location list expression)
#
# The location list in .debug_loc.dwo contains a DW_LLE_startx_length entry
# (GNU extension encoding) whose expression is { DW_OP_call4 <target CU-relative offset> }.
#
# DWO ID is 0xdd.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.quad	0xdd                            # DW_AT_GNU_dwo_id

	# Abbrev 2: DW_TAG_subprogram "dead_func" (GNU_addr_index 0, tombstoned -> dead)
	.byte	2
	.byte	0                               # DW_AT_low_pc: GNU_addr_index index 0
	.asciz	"dead_func"                     # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "live_func" (GNU_addr_index 1, live, has children)
	.byte	3
	.byte	1                               # DW_AT_low_pc: GNU_addr_index index 1
	.asciz	"live_func"                     # DW_AT_name

	# Abbrev 4: DW_TAG_variable "v" (DW_AT_location = sec_offset -> loclist)
	.byte	4
	.long	0                               # DW_AT_location: sec_offset (byte 0 of .debug_loc.dwo)

	# End of live_func children
	.byte	0

	# Abbrev 2: DW_TAG_subprogram "target" (GNU_addr_index 2, tombstoned, kept alive by loclist ref)
.Ltarget:
	.byte	2
	.byte	2                               # DW_AT_low_pc: GNU_addr_index index 2
	.asciz	"target"                        # DW_AT_name

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_loc.dwo,"e",@progbits
	# GNU split DWARF uses DW_LLE entry types even in DWARF4.
	# DW_LLE_startx_length
	.byte	0x03                            # DW_LLE_startx_length
	.byte	1                               # begin: GNU_addr_index 1 (ULEB128)
	.long	0x10                            # length (4 bytes)
	.short	5                               # Expression length (2 bytes)
	# NB: It obviously doesn't make any real sense to DW_OP_call4 a
	# DW_TAG_subprogram. The point here is just to test the mark-and-sweep
	# of the DIEs.
	.byte	0x99                            # DW_OP_call4
	.long	.Ltarget-.Ldebug_info_dwo_start+4 # 4-byte CU-relative offset of target
	# DW_LLE_end_of_list
	.byte	0x00

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children,
	#           DW_AT_GNU_dwo_id(data8)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.uleb128	0x2131                  # DW_AT_GNU_dwo_id
	.uleb128	7                       # DW_FORM_data8
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(GNU_addr_index) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.uleb128	0x1f01                  # DW_FORM_GNU_addr_index
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, has children, DW_AT_low_pc(GNU_addr_index) + DW_AT_name(string)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.uleb128	0x1f01                  # DW_FORM_GNU_addr_index
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_variable, no children, DW_AT_location(sec_offset)
	.byte	4                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
