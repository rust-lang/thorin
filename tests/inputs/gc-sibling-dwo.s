# .dwo file for gc-sibling.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram "live_func": DW_AT_low_pc = addrx 0 (live), DW_AT_sibling -> dead_func (children)
#       base_type "int"
#     subprogram "dead_func": DW_AT_low_pc = addrx 1 (tombstoned), DW_AT_sibling -> survivor (children)
#       base_type "float"
#     subprogram "survivor": DW_AT_low_pc = addrx 2 (live), no children
#     structure_type "MyStruct" (children)
#       subprogram "kept_method": DW_AT_low_pc = addrx 3 (live), DW_AT_sibling -> removed_method (children)
#         base_type "char"
#       subprogram "removed_method": DW_AT_low_pc = addrx 4 (tombstoned), no children
#     structure_type "Neighbor" (children)
#       subprogram "neighbor_method": DW_AT_low_pc = addrx 5 (live), no children
#
# The DWO ID is 0xdeadc0de.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xdeadc0de                      # DWO ID
	# DIE tree begins at offset 0x14 (20 bytes into unit)

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# [0x15] Abbrev 2: DW_TAG_subprogram "live_func" (has children)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0
	.long	.Ldead_func-.Ldebug_info_dwo_start+4 # DW_AT_sibling: ref4 -> dead_func
	.asciz	"live_func"                     # DW_AT_name

	# child: base_type "int"
.Lint:
	.byte	3                               # Abbrev 3: DW_TAG_base_type
	.asciz	"int"                           # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	5                               # DW_AT_encoding (DW_ATE_signed)

	.byte	0                               # End Of Children Mark (live_func)

	# [dead_func] Abbrev 2: DW_TAG_subprogram "dead_func" (has children)
.Ldead_func:
	.byte	2
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.long	.Lsurvivor-.Ldebug_info_dwo_start+4 # DW_AT_sibling: ref4 -> survivor
	.asciz	"dead_func"                     # DW_AT_name

	# child: base_type "float"
.Lfloat:
	.byte	3                               # Abbrev 3: DW_TAG_base_type
	.asciz	"float"                         # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	4                               # DW_AT_encoding (DW_ATE_float)

	.byte	0                               # End Of Children Mark (dead_func)

	# [survivor] Abbrev 4: DW_TAG_subprogram "survivor" (no children)
.Lsurvivor:
	.byte	4
	.byte	2                               # DW_AT_low_pc: addrx index 2
	.asciz	"survivor"                      # DW_AT_name

	# Abbrev 5: DW_TAG_structure_type "MyStruct" (has children)
	.byte	5
	.asciz	"MyStruct"                      # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "kept_method" (has children, with sibling)
	.byte	2
	.byte	3                               # DW_AT_low_pc: addrx index 3
	.long	.Lremoved_method-.Ldebug_info_dwo_start+4 # DW_AT_sibling: ref4 -> removed_method
	.asciz	"kept_method"                   # DW_AT_name

	# child: base_type "char"
	.byte	3                               # Abbrev 3: DW_TAG_base_type
	.asciz	"char"                          # DW_AT_name
	.byte	1                               # DW_AT_byte_size
	.byte	8                               # DW_AT_encoding (DW_ATE_unsigned_char)

	.byte	0                               # End Of Children Mark (kept_method)

	# Abbrev 4: DW_TAG_subprogram "removed_method" (no children)
.Lremoved_method:
	.byte	4
	.byte	4                               # DW_AT_low_pc: addrx index 4
	.asciz	"removed_method"                # DW_AT_name

	.byte	0                               # End Of Children Mark (MyStruct)

	# Abbrev 5: DW_TAG_structure_type "Neighbor" (has children)
	.byte	5
	.asciz	"Neighbor"                      # DW_AT_name

	# Abbrev 4: DW_TAG_subprogram "neighbor_method" (no children)
	.byte	4
	.byte	5                               # DW_AT_low_pc: addrx index 5
	.asciz	"neighbor_method"               # DW_AT_name

	.byte	0                               # End Of Children Mark (Neighbor)

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, no attrs
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, has children, DW_AT_low_pc(addrx) + DW_AT_sibling(ref4) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	1                               # DW_AT_sibling
	.byte	19                              # DW_FORM_ref4
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_base_type, no children, DW_AT_name(string) + DW_AT_byte_size(data1) + DW_AT_encoding(data1)
	.byte	3                               # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	62                              # DW_AT_encoding
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_name(string)
	.byte	4                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 5: DW_TAG_structure_type, has children, DW_AT_name(string)
	.byte	5                               # Abbreviation Code
	.byte	19                              # DW_TAG_structure_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
