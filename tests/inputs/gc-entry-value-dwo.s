# .dwo file for gc-entry-value.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children)
#     subprogram (dead_func): DW_AT_low_pc = addrx 0 (tombstoned -> dead)
#     subprogram (live_func): DW_AT_low_pc = addrx 1 (live), has children
#       variable "v": DW_AT_location = exprloc {
#         DW_OP_entry_value(5, DW_OP_call4 <target>), DW_OP_stack_value
#       }
#     subprogram (target): DW_AT_low_pc = addrx 2 (tombstoned, kept alive by
#                           DW_OP_call4 inside entry_value)
#
# DWO ID is 0xbbbb.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xbbbb                          # DWO ID

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1

	# [0x15] Abbrev 2: DW_TAG_subprogram (dead_func - addrx 0 is tombstoned)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0

	# [0x17] Abbrev 3: DW_TAG_subprogram (live_func - addrx 1 is real, has children)
	.byte	3
	.byte	1                               # DW_AT_low_pc: addrx index 1

	# [0x19] Abbrev 4: DW_TAG_variable
	# DW_AT_location = exprloc, total expression length = 8 bytes:
	#   DW_OP_entry_value (0xa3)           1 byte
	#   ULEB128 sub-expression length (5)  1 byte
	#   DW_OP_call4 (0x99)                 1 byte
	#   4-byte LE CU-relative offset       4 bytes
	#   DW_OP_stack_value (0x9f)           1 byte
	.byte	4
	.byte	8                               # exprloc length = 8
	.byte	0xa3                            # DW_OP_entry_value
	.byte	5                               # sub-expression length = 5
	.byte	0x99                            # DW_OP_call4
	.long	.Ltarget-.Ldebug_info_dwo_start+4 # 4-byte CU-relative offset of target
	.byte	0x9f                            # DW_OP_stack_value

	.byte	0                               # End Of Children Mark (live_func)

	# [target] Abbrev 2: DW_TAG_subprogram (target, kept alive by DW_OP_call4)
.Ltarget:
	.byte	2
	.byte	2                               # DW_AT_low_pc: addrx index 2

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

	.byte	0                               # End of abbreviations
