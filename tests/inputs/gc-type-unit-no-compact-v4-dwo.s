# .dwo file for gc-type-unit-no-compact-v4.test
#
# DWARF4 split-compile unit AND a type unit in a SEPARATE .debug_types.dwo
# section. The presence of the type unit should prevent compaction of
# .debug_str_offsets.dwo, because the type unit shares that section with the
# compilation unit.
#
# Compile unit in .debug_info.dwo (DW_AT_GNU_dwo_id = 0xee):
#   compile_unit (children)
#     subprogram "live_func" (GNU_addr_index 0, live)
#     subprogram "dead_func" (GNU_addr_index 1, tombstoned)
#
# Type unit in .debug_types.dwo (type sig 0x1234):
#   type_unit (children)
#     base_type "int": DW_AT_name = GNU_str_index 4 -> "int"
#
# .debug_str_offsets.dwo has 5 entries (indices 0-4), NO header (DWARF4).
#
# After GC, dead_func should be removed from .debug_info, but the
# str_offsets table must NOT be compacted because the type unit in
# .debug_types.dwo also references entries in it.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	# DW_AT_name: GNU_str_index 0 -> "test.c"
	.byte	0
	# DW_AT_comp_dir: GNU_str_index 1 -> "/home"
	.byte	1
	# DW_AT_GNU_dwo_id: data8 = 0xee
	.quad	0xee

	# Abbrev 2: DW_TAG_subprogram "live_func" (GNU_addr_index 0, live)
	.byte	2
	.byte	0                               # DW_AT_low_pc: GNU_addr_index index 0
	# DW_AT_name: GNU_str_index 2 -> "live_func"
	.byte	2

	# Abbrev 2: DW_TAG_subprogram "dead_func" (GNU_addr_index 1, tombstoned)
	.byte	2
	.byte	1                               # DW_AT_low_pc: GNU_addr_index index 1
	# DW_AT_name: GNU_str_index 3 -> "dead_func"
	.byte	3

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_types.dwo,"e",@progbits

	# --- Type unit ---
	.long	.Ldebug_types_tu_end-.Ldebug_types_tu_start # Length of Unit
.Ldebug_types_tu_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size
	.quad	0x1234                          # Type signature
	.long	.Ltu_type_die-.Ldebug_types_tu_start # Type DIE offset

	# Abbrev 3: DW_TAG_type_unit (has children)
	.byte	3

.Ltu_type_die:
	# Abbrev 4: DW_TAG_base_type "int"
	.byte	4
	# DW_AT_name: GNU_str_index 4 -> "int"
	.byte	4

	.byte	0                               # End Of Children Mark (type_unit)
.Ldebug_types_tu_end:

	.section	.debug_str.dwo,"eMS",@progbits,1
.Lstr0:
	.asciz	"test.c"
.Lstr1:
	.asciz	"/home"
.Lstr2:
	.asciz	"live_func"
.Lstr3:
	.asciz	"dead_func"
.Lstr4:
	.asciz	"int"

	.section	.debug_str_offsets.dwo,"e",@progbits
	# DWARF4: no header, just raw offset entries (4 bytes each, DWARF32)
	.long	.Lstr0-.debug_str.dwo           # Index 0: "test.c"
	.long	.Lstr1-.debug_str.dwo           # Index 1: "/home"
	.long	.Lstr2-.debug_str.dwo           # Index 2: "live_func"
	.long	.Lstr3-.debug_str.dwo           # Index 3: "dead_func"
	.long	.Lstr4-.debug_str.dwo           # Index 4: "int"

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

	# Abbrev 3: DW_TAG_type_unit, has children (no attributes)
	.byte	3                               # Abbreviation Code
	.byte	0x41                            # DW_TAG_type_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_base_type, no children,
	#           DW_AT_name(GNU_str_index)
	.byte	4                               # Abbreviation Code
	.byte	0x24                            # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.uleb128	3                       # DW_AT_name
	.uleb128	0x1f02                  # DW_FORM_GNU_str_index
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
