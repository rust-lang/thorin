# .dwo file for gc-retained-edge.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     namespace: DW_AT_type = ref4 -> base_type  (Retained, ancestor of live subprogram)
#       subprogram: DW_AT_low_pc = addrx 0 (tombstoned -> dead)
#       subprogram: DW_AT_low_pc = addrx 1 (live)
#     base_type  (only reachable via namespace's DW_AT_type)
#
# The DWO ID is 0xcafebabe.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xcafebabe                      # DWO ID
	# DIE tree begins at offset 0x14 (20 bytes into unit)

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# [0x15] Abbrev 2: DW_TAG_namespace (has children), DW_AT_type = ref4 -> base_type
	.byte	2
	.long	.Lbase_type-.Ldebug_info_dwo_start+4 # DW_AT_type: CU-relative ref4 to base_type

	# [0x1a] Abbrev 3: DW_TAG_subprogram (dead - addrx 0 is tombstoned)
	.byte	3
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# [0x1c] Abbrev 3: DW_TAG_subprogram (live - addrx 1 is real)
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1

	.byte	0                               # End Of Children Mark (namespace)

	# base_type (referenced by namespace's DW_AT_type)
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

	# Abbrev 2: DW_TAG_namespace, has children, DW_AT_type(ref4)
	.byte	2                               # Abbreviation Code
	.byte	57                              # DW_TAG_namespace
	.byte	1                               # DW_CHILDREN_yes
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_base_type, no children, no attrs
	.byte	4                               # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
