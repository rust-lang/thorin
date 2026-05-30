# .dwo file for gc-expr-ops.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram "dead1":    DW_AT_low_pc = addrx 0 (tombstoned -> dead, removed by GC)
#     subprogram "caller":   DW_AT_low_pc = addrx 1 (live),
#                            DW_AT_frame_base = exprloc { DW_OP_call2 <callee> }
#     subprogram "callee":   DW_AT_low_pc = addrx 2 (tombstoned, kept alive by DW_OP_call2)
#     subprogram "paramfn":  DW_AT_low_pc = addrx 3 (live), has children
#       formal_parameter:    DW_AT_location = exprloc { DW_OP_GNU_parameter_ref <paramtgt> }
#     subprogram "paramtgt": DW_AT_low_pc = addrx 4 (tombstoned, kept alive by DW_OP_GNU_parameter_ref)
#
# DWO ID is 0x66.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x66                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# Abbrev 2: DW_TAG_subprogram "dead1" (addrx 0, tombstoned -> dead)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# Abbrev 3: DW_TAG_subprogram "caller" (addrx 1, live)
	# DW_AT_frame_base = exprloc { DW_OP_call2 <callee> }
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.byte	3                               # exprloc length = 3 (DW_OP_call2 + 2-byte offset)
	.byte	0x98                            # DW_OP_call2
	.short	.Lcallee-.Ldebug_info_dwo_start+4 # 2-byte CU-relative offset of callee

	# Abbrev 2: DW_TAG_subprogram "callee" (addrx 2, tombstoned, kept alive)
.Lcallee:
	.byte	2
	.byte	2                               # DW_AT_low_pc: addrx index 2

	# Abbrev 4: DW_TAG_subprogram "paramfn" (addrx 3, live, has children)
	.byte	4
	.byte	3                               # DW_AT_low_pc: addrx index 3

	# Abbrev 5: DW_TAG_formal_parameter
	# DW_AT_location = exprloc { DW_OP_GNU_parameter_ref <paramtgt> }
	.byte	5
	.byte	5                               # exprloc length = 5 (opcode + 4-byte offset)
	.byte	0xfa                            # DW_OP_GNU_parameter_ref
	.long	.Lparamtgt-.Ldebug_info_dwo_start+4 # 4-byte CU-relative offset of paramtgt

	.byte	0                               # End Of Children Mark (paramfn)

	# Abbrev 2: DW_TAG_subprogram "paramtgt" (addrx 4, tombstoned, kept alive)
.Lparamtgt:
	.byte	2
	.byte	4                               # DW_AT_low_pc: addrx index 4

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

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(addrx) + DW_AT_frame_base(exprloc)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
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

	# Abbrev 5: DW_TAG_formal_parameter, no children, DW_AT_location(exprloc)
	.byte	5                               # Abbreviation Code
	.byte	5                               # DW_TAG_formal_parameter
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
