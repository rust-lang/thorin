# .dwo file for gc-dead-subprogram.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram: DW_AT_low_pc = addrx4 0 (will be tombstoned -> dead)
#     subprogram: DW_AT_low_pc = addrx4 1 (live), DW_AT_type = ref4 -> base_type
#     base_type  (kept alive by the live subprogram's DW_AT_type)
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

	# [0x15] Abbrev 2: DW_TAG_subprogram (dead - addrx4 0 is tombstoned)
	.byte	2
	.long	0                               # DW_AT_low_pc: addrx4 index 0

	# [0x1a] Abbrev 3: DW_TAG_subprogram (live - addrx4 1 is real)
	.byte	3
	.long	1                               # DW_AT_low_pc: addrx4 index 1
	.long	.Lbase_type-.Ldebug_info_dwo_start+4 # DW_AT_type: ref4 to base_type

	# base_type (referenced by live subprogram)
.Lbase_type:
	.byte	4                               # Abbrev 4: DW_TAG_base_type

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, no attrs
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx4)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	0x2c                            # DW_FORM_addrx4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx4) + DW_AT_type(ref4)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	0x2c                            # DW_FORM_addrx4
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_base_type, no children, no attrs
	.byte	4                               # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
