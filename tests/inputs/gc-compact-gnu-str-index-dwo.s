# .dwo file for gc-compact-gnu-str-index.test
#
# DWARF4 split-compile unit (GNU extension) containing:
#   compile_unit (children, DW_AT_name = GNU_str_index 0 -> "test.c",
#                           DW_AT_comp_dir = GNU_str_index 1 -> "/home",
#                           DW_AT_GNU_dwo_id = 0xee)
#     subprogram "dead_func" (GNU_addr_index 0, tombstoned):
#         DW_AT_name = GNU_str_index 2 -> "dead_func"
#     subprogram "live_func" (GNU_addr_index 1, live):
#         DW_AT_name = GNU_str_index 3 -> "live_func"
#
# .debug_str_offsets.dwo has 4 entries (indices 0-3), NO header (DWARF4).
# .debug_str.dwo has 4 strings: "test.c", "/home", "dead_func", "live_func".
#
# After GC, dead_func is removed. Its string "dead_func" at str index 2
# should be removed from the str_offsets table, compacting it from 4 to 3
# entries. Crucially, "live_func" moves from index 3 to index 2, so the
# DW_FORM_GNU_str_index attribute for the surviving subprogram must be
# remapped. Without the fix, the old index 3 is copied verbatim and points
# to garbage.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	# DW_AT_name: GNU_str_index, ULEB128 index 0 -> "test.c"
	.byte	0
	# DW_AT_comp_dir: GNU_str_index, ULEB128 index 1 -> "/home"
	.byte	1
	# DW_AT_GNU_dwo_id: data8 = 0xee
	.quad	0xee

	# Abbrev 2: DW_TAG_subprogram "dead_func" (GNU_addr_index 0, tombstoned)
	.byte	2
	.byte	0                               # DW_AT_low_pc: GNU_addr_index index 0
	# DW_AT_name: GNU_str_index, ULEB128 index 2 -> "dead_func"
	.byte	2

	# Abbrev 2: DW_TAG_subprogram "live_func" (GNU_addr_index 1, live)
	.byte	2
	.byte	1                               # DW_AT_low_pc: GNU_addr_index index 1
	# DW_AT_name: GNU_str_index, ULEB128 index 3 -> "live_func"
	.byte	3

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
	# DWARF4: no header, just raw offset entries (4 bytes each, DWARF32)
	.long	.Lstr0-.debug_str.dwo           # Index 0: "test.c"
	.long	.Lstr1-.debug_str.dwo           # Index 1: "/home"
	.long	.Lstr2-.debug_str.dwo           # Index 2: "dead_func"
	.long	.Lstr3-.debug_str.dwo           # Index 3: "live_func"

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children,
	#           DW_AT_name(GNU_str_index) + DW_AT_comp_dir(GNU_str_index) +
	#           DW_AT_GNU_dwo_id(data8)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.uleb128	3                       # DW_AT_name
	.uleb128	0x1f02                  # DW_FORM_GNU_str_index
	.uleb128	0x1b                    # DW_AT_comp_dir
	.uleb128	0x1f02                  # DW_FORM_GNU_str_index
	.uleb128	0x2131                  # DW_AT_GNU_dwo_id
	.uleb128	7                       # DW_FORM_data8
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children,
	#           DW_AT_low_pc(GNU_addr_index) + DW_AT_name(GNU_str_index)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.uleb128	17                      # DW_AT_low_pc
	.uleb128	0x1f01                  # DW_FORM_GNU_addr_index
	.uleb128	3                       # DW_AT_name
	.uleb128	0x1f02                  # DW_FORM_GNU_str_index
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
