# .dwo file for gc-variable-root.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram: DW_AT_low_pc = addrx 0 (will be tombstoned -> dead)
#     variable "live_var": DW_AT_location = exprloc { DW_OP_addrx 1 } (live),
#                          DW_AT_type = ref4 -> base_type
#     variable "dead_var": DW_AT_location = exprloc { DW_OP_addrx 2 } (tombstoned -> dead)
#     base_type "int": name, byte_size=4, encoding=DW_ATE_signed
#                      (kept alive by live_var's DW_AT_type)
#
# The DWO ID is 0xdeadbeef.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xdeadbeef                      # DWO ID
	# DIE tree begins at offset 0x14 (20 bytes into unit)

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_subprogram (dead - addrx 0 is tombstoned)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# Abbrev 3: DW_TAG_variable "live_var" (live - addrx 1 is real)
	.byte	3
	.asciz	"live_var"                      # DW_AT_name
	.byte	2                               # DW_AT_location: exprloc length (2 bytes)
	.byte	0xa1                            # DW_OP_addrx
	.byte	1                               # ULEB128 address index 1
	.long	.Lbase_type-.Ldebug_info_dwo_start+4 # DW_AT_type: ref4 to base_type

	# Abbrev 4: DW_TAG_variable "dead_var" (dead - addrx 2 is tombstoned)
	.byte	4
	.asciz	"dead_var"                      # DW_AT_name
	.byte	2                               # DW_AT_location: exprloc length (2 bytes)
	.byte	0xa1                            # DW_OP_addrx
	.byte	2                               # ULEB128 address index 2

	# base_type "int" (referenced by live_var's DW_AT_type)
.Lbase_type:
	.byte	5                               # Abbrev 5: DW_TAG_base_type
	.asciz	"int"                           # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	5                               # DW_AT_encoding: DW_ATE_signed

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

	# Abbrev 3: DW_TAG_variable, no children, DW_AT_name(string) + DW_AT_location(exprloc) + DW_AT_type(ref4)
	.byte	3                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_variable, no children, DW_AT_name(string) + DW_AT_location(exprloc)
	.byte	4                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
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
