# .dwo file for gc-unreferenced-dwo.test
#
# DWARF5 split-compile unit with DWO ID 0xbb, which does NOT match
# the executable (which references 0xaa). The .dwo has str_offsets.
#
# When passed via -i with --gc, the unit should still be included in
# the output with its str_offsets section intact, even though GC
# cannot be performed (no executable data for this dwo_id).

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xbb                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.byte	0                               # DW_AT_name: strx1 index 0 -> "other.c"
	.byte	1                               # DW_AT_comp_dir: strx1 index 1 -> "/src"

	# Abbrev 2: DW_TAG_subprogram (no children)
	.byte	2
	.byte	2                               # DW_AT_name: strx1 index 2 -> "some_func"

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_str.dwo,"eMS",@progbits,1
.Lstr0:
	.asciz	"other.c"
.Lstr1:
	.asciz	"/src"
.Lstr2:
	.asciz	"some_func"

	.section	.debug_str_offsets.dwo,"e",@progbits
	.long	.Lstr_offsets_end-.Lstr_offsets_start # Unit length
.Lstr_offsets_start:
	.short	5                               # Version
	.short	0                               # Padding
	.long	.Lstr0-.debug_str.dwo           # Index 0: "other.c"
	.long	.Lstr1-.debug_str.dwo           # Index 1: "/src"
	.long	.Lstr2-.debug_str.dwo           # Index 2: "some_func"
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

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_name(strx1)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
