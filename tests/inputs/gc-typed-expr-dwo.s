# .dwo file for gc-typed-expr.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram "dead_func": DW_AT_low_pc = addrx 0 (tombstoned -> dead),
#                              DW_AT_type = ref4 -> dead_type
#     base_type "dead_type": byte_size=8, encoding=DW_ATE_signed (only reachable
#                            from dead_func, so removed by GC)
#     subprogram "conv_func": DW_AT_low_pc = addrx 1 (live), has children
#       variable "v1": DW_AT_location = exprloc { DW_OP_lit0, DW_OP_convert <conv_type>, DW_OP_stack_value }
#       null
#     base_type "conv_type": byte_size=4, encoding=DW_ATE_signed
#     subprogram "ct_func": DW_AT_low_pc = addrx 2 (live), has children
#       variable "v2": DW_AT_location = exprloc { DW_OP_const_type <ct_type> 4 <4 bytes> }
#       null
#     base_type "ct_type": byte_size=4, encoding=DW_ATE_float
#     null
#
# DWO ID is 0x77.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x77                            # DWO ID

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_subprogram (dead - addrx 0 is tombstoned, DW_AT_type -> dead_type)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0
	.long	.Ldead_type-.Ldebug_info_dwo_start+4 # DW_AT_type: ref4 to dead_type

	# Abbrev 3: DW_TAG_base_type (dead_type, only reachable from dead_func)
.Ldead_type:
	.byte	3
	.asciz	"dt"                            # DW_AT_name
	.byte	8                               # DW_AT_byte_size
	.byte	5                               # DW_AT_encoding: DW_ATE_signed

	# Abbrev 4: DW_TAG_subprogram (conv_func - addrx 1, live, has children)
	.byte	4
	.byte	1                               # DW_AT_low_pc: addrx index 1

	# Abbrev 5: DW_TAG_variable (v1)
	# DW_AT_location: exprloc { DW_OP_lit0, DW_OP_convert <conv_type>, DW_OP_stack_value }
	.byte	5
	.byte	4                               # exprloc length = 4 bytes
	.byte	0x30                            # DW_OP_lit0
	.byte	0xa8                            # DW_OP_convert
	.byte	.Lconv_type-.Ldebug_info_dwo_start+4 # ULEB128 CU-relative offset of conv_type
	.byte	0x9f                            # DW_OP_stack_value

	.byte	0                               # End Of Children Mark (conv_func)

	# Abbrev 3: DW_TAG_base_type (conv_type, kept alive by DW_OP_convert)
.Lconv_type:
	.byte	3
	.asciz	"it"                            # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	5                               # DW_AT_encoding: DW_ATE_signed

	# Abbrev 4: DW_TAG_subprogram (ct_func - addrx 2, live, has children)
	.byte	4
	.byte	2                               # DW_AT_low_pc: addrx index 2

	# Abbrev 5: DW_TAG_variable (v2)
	# DW_AT_location: exprloc { DW_OP_const_type <ct_type> 4 <4 bytes of data> }
	.byte	5
	.byte	7                               # exprloc length = 7 bytes
	.byte	0xa4                            # DW_OP_const_type
	.byte	.Lct_type-.Ldebug_info_dwo_start+4 # ULEB128 CU-relative offset of ct_type
	.byte	4                               # size = 4 bytes
	.byte	0x01                            # literal data byte 0
	.byte	0x00                            # literal data byte 1
	.byte	0x00                            # literal data byte 2
	.byte	0x00                            # literal data byte 3

	.byte	0                               # End Of Children Mark (ct_func)

	# Abbrev 3: DW_TAG_base_type (ct_type, kept alive by DW_OP_const_type)
.Lct_type:
	.byte	3
	.asciz	"ft"                            # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	4                               # DW_AT_encoding: DW_ATE_float

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, no attrs
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_type(ref4)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
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

	# Abbrev 4: DW_TAG_subprogram, has children, DW_AT_low_pc(addrx)
	.byte	4                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 5: DW_TAG_variable, no children, DW_AT_location(exprloc)
	.byte	5                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
