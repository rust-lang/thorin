# .dwo file for gc-duplicate-dwoid.test
#
# DWARF5 split-compile unit with DWO ID 0xdd containing two
# subprograms. Each uses a different addrx index for DW_AT_low_pc:
#   subprogram "func_a": addrx4 index 0
#   subprogram "func_b": addrx4 index 1
#
# Two separate executables reference this .dwo. Exec1 has index 0 live
# and index 1 tombstoned; exec2 has the reverse. Both subprograms
# should survive GC because each is live in at least one executable.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xdd                            # DWO ID

	# [0x14] Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.byte	0                               # DW_AT_name: strx1 index 0 -> "test.c"

	# Abbrev 2: DW_TAG_subprogram "func_a" (addrx4 index 0)
	.byte	2
	.long	0                               # DW_AT_low_pc: addrx4 index 0
	.byte	1                               # DW_AT_name: strx1 index 1 -> "func_a"

	# Abbrev 2: DW_TAG_subprogram "func_b" (addrx4 index 1)
	.byte	2
	.long	1                               # DW_AT_low_pc: addrx4 index 1
	.byte	2                               # DW_AT_name: strx1 index 2 -> "func_b"

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_str.dwo,"eMS",@progbits,1
.Lstr0:
	.asciz	"test.c"
.Lstr1:
	.asciz	"func_a"
.Lstr2:
	.asciz	"func_b"

	.section	.debug_str_offsets.dwo,"e",@progbits
	.long	.Lstr_offsets_end-.Lstr_offsets_start # Unit length
.Lstr_offsets_start:
	.short	5                               # Version
	.short	0                               # Padding
	.long	.Lstr0-.debug_str.dwo           # Index 0: "test.c"
	.long	.Lstr1-.debug_str.dwo           # Index 1: "func_a"
	.long	.Lstr2-.debug_str.dwo           # Index 2: "func_b"
.Lstr_offsets_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, DW_AT_name(strx1)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children,
	#           DW_AT_low_pc(addrx4) + DW_AT_name(strx1)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	0x2c                            # DW_FORM_addrx4
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
