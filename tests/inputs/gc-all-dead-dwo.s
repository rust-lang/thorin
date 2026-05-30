# .dwo file for gc-all-dead.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram: DW_AT_low_pc = addrx 0 (will be tombstoned -> dead)
#     subprogram: DW_AT_low_pc = addrx 1 (will be tombstoned -> dead)
#
# Every subprogram is dead, so GC removes all children. The compile_unit
# itself must survive because the skeleton CU in the executable references it.
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

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_subprogram (dead - addrx 0 is tombstoned)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# Abbrev 2: DW_TAG_subprogram (dead - addrx 1 is also tombstoned)
	.byte	2
	.byte	1                               # DW_AT_low_pc: addrx index 1

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

	.byte	0                               # End of abbreviations
