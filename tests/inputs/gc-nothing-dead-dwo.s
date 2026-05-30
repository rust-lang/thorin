# .dwo file for gc-nothing-dead.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram: DW_AT_low_pc = addrx1 0 (live)
#     subprogram: DW_AT_low_pc = addrx1 1 (live)
#
# Both subprograms are live, so nothing should be pruned.
# The DWO ID is 0x1234.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x1234                          # DWO ID
	# DIE tree begins at offset 0x14 (20 bytes into unit)

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# [0x15] Abbrev 2: DW_TAG_subprogram (live - addrx1 0)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx1 index 0

	# [0x17] Abbrev 2: DW_TAG_subprogram (live - addrx1 1)
	.byte	2
	.byte	1                               # DW_AT_low_pc: addrx1 index 1

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, no attrs
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx1)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	0x29                            # DW_FORM_addrx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
