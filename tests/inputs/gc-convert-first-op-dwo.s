# .dwo file for gc-convert-first-op.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram "dead_func": DW_AT_low_pc = addrx 0 (tombstoned -> dead),
#                             no children (removed by GC, shifts later offsets)
#     subprogram "live_func": DW_AT_low_pc = addrx 1 (live), has children
#       variable "v": DW_AT_location = exprloc { DW_OP_convert <conv_type> }
#                     The expression is exactly 2 bytes: [0xa8, conv_type_offset].
#                     0xa8 (DW_OP_convert) is the FIRST byte of the expression,
#                     which is what distinguishes this test from gc-typed-expr.
#       null
#     base_type "conv_type": DW_AT_name="ct", byte_size=4, encoding=DW_ATE_float
#                            (kept alive by DW_OP_convert)
#     null
#
# DWO ID is 0x42.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x42                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_subprogram (dead_func - addrx 0 is tombstoned, no children)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# Abbrev 3: DW_TAG_subprogram (live_func - addrx 1, live, has children)
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1

	# Abbrev 4: DW_TAG_variable (v)
	# DW_AT_location: exprloc { DW_OP_convert <conv_type> }
	# The expression is exactly 2 bytes; byte 0 is the 0xa8 opcode.
	.byte	4
	.byte	2                               # exprloc length = 2 bytes
	.byte	0xa8                            # DW_OP_convert (byte 0 of expression)
	.byte	.Lconv_type-.Ldebug_info_dwo_start+4 # ULEB128 CU-relative offset of conv_type

	.byte	0                               # End Of Children Mark (live_func)

	# Abbrev 5: DW_TAG_base_type (conv_type, kept alive by DW_OP_convert)
.Lconv_type:
	.byte	5
	.asciz	"ct"                            # DW_AT_name
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

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, has children, DW_AT_low_pc(addrx)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_variable, no children, DW_AT_location(exprloc)
	.byte	4                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 5: DW_TAG_base_type, no children, DW_AT_name(string) + DW_AT_byte_size(data1) + DW_AT_encoding(data1)
	.byte	5                               # Abbreviation Code
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

	.byte	0                               # End of abbreviations
