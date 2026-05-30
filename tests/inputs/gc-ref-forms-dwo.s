# .dwo file for gc-ref-forms.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram "dead": DW_AT_low_pc = addrx 0 (tombstoned -> dead)
#     subprogram "live_func": DW_AT_low_pc = addrx 1 (live), DW_AT_type = ref1 -> t_r1
#     base_type "t_r1": name, byte_size=4, encoding=DW_ATE_signed
#     subprogram "live_func2": DW_AT_low_pc = addrx 2 (live), DW_AT_type = ref2 -> t_r2
#     base_type "t_r2": name, byte_size=4, encoding=DW_ATE_unsigned
#     subprogram "live_func3": DW_AT_low_pc = addrx 3 (live), DW_AT_type = ref_udata -> t_ru
#     base_type "t_ru": name, byte_size=8, encoding=DW_ATE_float
#
# The DWO ID is 0xbeefcafe.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xbeefcafe                      # DWO ID
	# DIE tree begins at offset 0x14 (20 bytes into unit)

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# [0x15] Abbrev 2: DW_TAG_subprogram (dead - addrx 0 is tombstoned)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# [0x17] Abbrev 3: DW_TAG_subprogram (live - addrx 1), DW_AT_type = ref1
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.byte	.Lt_r1-.Ldebug_info_dwo_start+4 # DW_AT_type: ref1 to t_r1

	# [0x1a] base_type "t_r1" (referenced by live_func via ref1)
.Lt_r1:
	.byte	4                               # Abbrev 4: DW_TAG_base_type
	.asciz	"t_r1"                          # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	5                               # DW_AT_encoding (DW_ATE_signed)

	# [0x22] Abbrev 5: DW_TAG_subprogram (live - addrx 2), DW_AT_type = ref2
	.byte	5
	.byte	2                               # DW_AT_low_pc: addrx index 2
	.short	.Lt_r2-.Ldebug_info_dwo_start+4 # DW_AT_type: ref2 to t_r2

	# [0x26] base_type "t_r2" (referenced by live_func2 via ref2)
.Lt_r2:
	.byte	4                               # Abbrev 4: DW_TAG_base_type
	.asciz	"t_r2"                          # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	7                               # DW_AT_encoding (DW_ATE_unsigned)

	# [0x2e] Abbrev 6: DW_TAG_subprogram (live - addrx 3), DW_AT_type = ref_udata
	.byte	6
	.byte	3                               # DW_AT_low_pc: addrx index 3
	.byte	.Lt_ru-.Ldebug_info_dwo_start+4 # DW_AT_type: ref_udata (ULEB128) to t_ru

	# [0x31] base_type "t_ru" (referenced by live_func3 via ref_udata)
.Lt_ru:
	.byte	4                               # Abbrev 4: DW_TAG_base_type
	.asciz	"t_ru"                          # DW_AT_name
	.byte	8                               # DW_AT_byte_size
	.byte	4                               # DW_AT_encoding (DW_ATE_float)

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

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_type(ref1)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	73                              # DW_AT_type
	.byte	17                              # DW_FORM_ref1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_base_type, no children, DW_AT_name(string) + DW_AT_byte_size(data1) + DW_AT_encoding(data1)
	.byte	4                               # Abbreviation Code
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

	# Abbrev 5: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_type(ref2)
	.byte	5                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	73                              # DW_AT_type
	.byte	18                              # DW_FORM_ref2
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 6: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_type(ref_udata)
	.byte	6                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	73                              # DW_AT_type
	.byte	21                              # DW_FORM_ref_udata
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
