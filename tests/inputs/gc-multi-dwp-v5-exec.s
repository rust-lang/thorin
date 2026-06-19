# Fake executable for gc-multi-dwp-v5.test
#
# Provides garbage-collection address data for two compilation units that are
# re-packaged from a multi-CU `.dwp` input:
#   DWO ID 0xbb (from gc-compact-loclists-dwo.s)
#   DWO ID 0xcc (from gc-loclist-dwo.s)
#
# Each skeleton CU has its own DW_AT_addr_base into a per-CU address table.
# The `.dwo` references are never loaded: the `.dwp` is processed first, so the
# units are already contained and the executable only contributes addr data.
#
# Both address tables use the same pattern:
#   index 0: 0xffffffffffffffff (tombstone)
#   index 1: 0x1000             (live)
#   index 2: 0xffffffffffffffff (tombstone)

	.section	.debug_info,"",@progbits
	# Skeleton CU for DWO ID 0xbb
	.long	.Ldebug_info_bb_end-.Ldebug_info_bb_start # Length of Unit
.Ldebug_info_bb_start:
	.short	5                               # DWARF version number
	.byte	4                               # DW_UT_skeleton
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xbb                            # DWO ID
	.byte	1                               # Abbrev 1: DW_TAG_compile_unit
	.long	.Laddr_table_bb                 # DW_AT_addr_base
	.asciz	"ignored-bb.dwo"                # DW_AT_dwo_name (never loaded)
.Ldebug_info_bb_end:

	# Skeleton CU for DWO ID 0xcc
	.long	.Ldebug_info_cc_end-.Ldebug_info_cc_start # Length of Unit
.Ldebug_info_cc_start:
	.short	5                               # DWARF version number
	.byte	4                               # DW_UT_skeleton
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xcc                            # DWO ID
	.byte	1                               # Abbrev 1: DW_TAG_compile_unit
	.long	.Laddr_table_cc                 # DW_AT_addr_base
	.asciz	"ignored-cc.dwo"                # DW_AT_dwo_name (never loaded)
.Ldebug_info_cc_end:

	.section	.debug_abbrev,"",@progbits
	# Abbrev 1: DW_TAG_compile_unit, no children
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	0                               # DW_CHILDREN_no
	.byte	115                             # DW_AT_addr_base
	.byte	23                              # DW_FORM_sec_offset
	.byte	118                             # DW_AT_dwo_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	0                               # End of abbreviations

	.section	.debug_addr,"",@progbits
	# DWARF5 .debug_addr header
	.long	.Laddr_end-.Laddr_start         # Length
.Laddr_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
.Laddr_table_bb:
	# Address table for DWO ID 0xbb
	.quad	0xffffffffffffffff              # Index 0: tombstone
	.quad	0x1000                          # Index 1: live
	.quad	0xffffffffffffffff              # Index 2: tombstone
.Laddr_table_cc:
	# Address table for DWO ID 0xcc
	.quad	0xffffffffffffffff              # Index 0: tombstone
	.quad	0x1000                          # Index 1: live
	.quad	0xffffffffffffffff              # Index 2: tombstone
.Laddr_end:
