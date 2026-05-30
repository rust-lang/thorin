# .dwo file for gc-exprloc-call.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram (caller): DW_AT_low_pc = addrx 0 (live),
#                           DW_AT_frame_base = exprloc { DW_OP_call4 <callee> }
#     base_type  (dead, never referenced — placed before callee so removing
#                 it shifts the callee's offset, exercising operand patching)
#     subprogram (callee): DW_AT_low_pc = addrx 1 (tombstoned, not a root,
#                           kept alive by DW_OP_call4 reference)
#
# DWO ID is 0x55.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x55                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_subprogram (caller)
	# DW_AT_low_pc: addrx index 0 (live)
	# DW_AT_frame_base: exprloc { DW_OP_call4 <callee CU-relative offset> }
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0
	.byte	5                               # exprloc length = 5
	.byte	0x99                            # DW_OP_call4
	.long	.Lcallee-.Ldebug_info_dwo_start+4 # 4-byte CU-relative offset of callee

	# Abbrev 3: DW_TAG_base_type (dead, never referenced)
	.byte	3

	# Abbrev 4: DW_TAG_subprogram (callee, kept alive by DW_OP_call4)
.Lcallee:
	.byte	4
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

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_frame_base(exprloc)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_base_type, no children, no attrs
	.byte	3                               # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx)
	.byte	4                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
