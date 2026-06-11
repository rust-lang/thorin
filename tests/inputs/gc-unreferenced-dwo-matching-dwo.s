# Minimal .dwo file with DWO ID 0xaa that matches the executable.
# Used alongside gc-unreferenced-dwo-dwo.s (0xbb) in the test.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xaa                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (no children)
	.byte	1
	.byte	0                               # DW_AT_name: strx1 index 0 -> "main.c"
.Ldebug_info_dwo_end:

	.section	.debug_str.dwo,"eMS",@progbits,1
.Lstr0:
	.asciz	"main.c"

	.section	.debug_str_offsets.dwo,"e",@progbits
	.long	.Lstr_offsets_end-.Lstr_offsets_start # Unit length
.Lstr_offsets_start:
	.short	5                               # Version
	.short	0                               # Padding
	.long	.Lstr0-.debug_str.dwo           # Index 0: "main.c"
.Lstr_offsets_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, no children, DW_AT_name(strx1)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
