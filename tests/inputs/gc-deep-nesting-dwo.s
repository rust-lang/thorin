# .dwo file for gc-deep-nesting.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     structure_type "MyClass" (children, byte_size=1)
#       subprogram "dead_method": DW_AT_low_pc = addrx2 0 (tombstoned -> dead)
#       subprogram "live_method": DW_AT_low_pc = addrx2 1 (live)
#       null (end structure_type)
#     subprogram "outer": DW_AT_low_pc = addrx3 2 (tombstoned -> Retained), has children
#       subprogram "dead_inner": DW_AT_low_pc = addrx2 3 (tombstoned -> dead)
#       subprogram "live_inner": DW_AT_low_pc = addrx2 4 (live)
#       null (end outer)
#     null (end compile_unit)
#
# The DWO ID is 0xdeed.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xdeed                          # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_structure_type "MyClass" (has children, byte_size=1)
	.byte	2
	.asciz	"MyClass"                       # DW_AT_name
	.byte	1                               # DW_AT_byte_size

	# Abbrev 3: DW_TAG_subprogram "dead_method" (dead - addrx2 0 is tombstoned)
	.byte	3
	.short	0                               # DW_AT_low_pc: addrx2 index 0
	.asciz	"dead_method"                   # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "live_method" (live - addrx2 1 is real)
	.byte	3
	.short	1                               # DW_AT_low_pc: addrx2 index 1
	.asciz	"live_method"                   # DW_AT_name

	.byte	0                               # End Of Children Mark (structure_type)

	# Abbrev 4: DW_TAG_subprogram "outer" (has children, addrx3 2 is tombstoned -> Retained)
	.byte	4
	.byte	2                               # DW_AT_low_pc: addrx3 index 2 (3-byte little-endian)
	.short	0
	.asciz	"outer"                         # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "dead_inner" (dead - addrx2 3 is tombstoned)
	.byte	3
	.short	3                               # DW_AT_low_pc: addrx2 index 3
	.asciz	"dead_inner"                    # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "live_inner" (live - addrx2 4 is real)
	.byte	3
	.short	4                               # DW_AT_low_pc: addrx2 index 4
	.asciz	"live_inner"                    # DW_AT_name

	.byte	0                               # End Of Children Mark (outer)
	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, no attrs
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_structure_type, has children, DW_AT_name(string) + DW_AT_byte_size(data1)
	.byte	2                               # Abbreviation Code
	.byte	19                              # DW_TAG_structure_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx2) + DW_AT_name(string)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	0x2a                            # DW_FORM_addrx2
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_subprogram, has children, DW_AT_low_pc(addrx3) + DW_AT_name(string)
	.byte	4                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	0x2b                            # DW_FORM_addrx3
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
