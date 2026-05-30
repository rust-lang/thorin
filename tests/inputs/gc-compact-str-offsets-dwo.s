# .dwo file for gc-compact-str-offsets.test
#
# DWARF5 split-compile unit containing:
#   compile_unit (children, DW_AT_name = strx1 0 -> "test.c",
#                           DW_AT_comp_dir = strx1 1 -> "/home")
#     subprogram "dead_func" (addrx 0, tombstoned): DW_AT_name = strx3 2 -> "dead_func"
#     subprogram "live_func" (addrx 1, live): DW_AT_name = strx3 3 -> "live_func"
#
# .debug_str_offsets.dwo has 4 entries (indices 0-3).
# .debug_str.dwo has 4 strings: "test.c", "/home", "dead_func", "live_func".
#
# After GC, dead_func is removed. Its string "dead_func" at strx index 2
# is removed from the str_offsets table, compacting it from 4 to 3 entries.
# Crucially, "live_func" moves from index 3 to index 2, so the
# DW_FORM_strx3 attribute for the surviving subprogram must be remapped.
# Without the fix, the old index 3 is copied verbatim and points to garbage.
#
# DWO ID is 0xee.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xee                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.byte	0                               # DW_AT_name: strx1 index 0 -> "test.c"
	.byte	1                               # DW_AT_comp_dir: strx1 index 1 -> "/home"

	# Abbrev 2: DW_TAG_subprogram "dead_func" (addrx 0, tombstoned)
	.byte	2
	.byte	0                               # DW_AT_low_pc: addrx index 0
	.byte	2, 0, 0                         # DW_AT_name: strx3 index 2 -> "dead_func"

	# Abbrev 2: DW_TAG_subprogram "live_func" (addrx 1, live)
	.byte	2
	.byte	1                               # DW_AT_low_pc: addrx index 1
	.byte	3, 0, 0                         # DW_AT_name: strx3 index 3 -> "live_func"

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_str.dwo,"eMS",@progbits,1
.Lstr0:
	.asciz	"test.c"
.Lstr1:
	.asciz	"/home"
.Lstr2:
	.asciz	"dead_func"
.Lstr3:
	.asciz	"live_func"

	.section	.debug_str_offsets.dwo,"e",@progbits
	# DWARF5 str_offsets header
	.long	.Lstr_offsets_end-.Lstr_offsets_start # Unit length
.Lstr_offsets_start:
	.short	5                               # Version
	.short	0                               # Padding
	# Offset table entries (4 entries, DWARF32 -> 4 bytes each)
	.long	.Lstr0-.debug_str.dwo           # Index 0: "test.c"
	.long	.Lstr1-.debug_str.dwo           # Index 1: "/home"
	.long	.Lstr2-.debug_str.dwo           # Index 2: "dead_func"
	.long	.Lstr3-.debug_str.dwo           # Index 3: "live_func"
.Lstr_offsets_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children,
	#           DW_AT_name(strx1) + DW_AT_comp_dir(strx1)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0x1b                            # DW_AT_comp_dir
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children,
	#           DW_AT_low_pc(addrx) + DW_AT_name(strx3)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	27                              # DW_FORM_addrx
	.byte	3                               # DW_AT_name
	.byte	0x27                            # DW_FORM_strx3
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
