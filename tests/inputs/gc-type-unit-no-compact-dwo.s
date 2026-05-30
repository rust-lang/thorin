# .dwo file for gc-type-unit-no-compact.test
#
# DWARF5 split-compile unit AND a split type unit in the same .debug_info.dwo.
# The presence of the type unit should prevent compaction of rnglists,
# loclists, and str_offsets offset tables, because the type unit shares
# those sections with the compilation unit.
#
# Compile unit (DW_UT_split_compile, DWO ID 0xee):
#   compile_unit (children)
#     subprogram "live_func" (rnglistx 0, live, has children)
#       variable "v": DW_AT_location = loclistx 0
#     subprogram "dead_func" (rnglistx 1, tombstoned, has children)
#       variable "w": DW_AT_location = loclistx 1
#
# Type unit (DW_UT_split_type, type sig 0x1234):
#   type_unit (children)
#     base_type "int": DW_AT_name = strx1 4 -> "int"
#
# .debug_str_offsets.dwo has 5 entries (indices 0-4).
# .debug_rnglists.dwo has 2 range lists.
# .debug_loclists.dwo has 2 location lists.
#
# After GC, dead_func and its variable should be removed from .debug_info,
# but the rnglists/loclists/str_offsets offset tables must NOT be compacted.

	.section	.debug_info.dwo,"e",@progbits

	# --- Compile unit ---
	.long	.Ldebug_info_cu_end-.Ldebug_info_cu_start # Length of Unit
.Ldebug_info_cu_start:
	.short	5                               # DWARF version number
	.byte	5                               # DW_UT_split_compile
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0xee                            # DWO ID

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.byte	0                               # DW_AT_name: strx1 index 0 -> "test.c"
	.byte	1                               # DW_AT_comp_dir: strx1 index 1 -> "/home"
	.long	.Lrnglists_table_base-.Lrnglists_section_start # DW_AT_rnglists_base
	.long	.Lloclists_table_base-.Lloclists_section_start # DW_AT_loclists_base

	# Abbrev 2: DW_TAG_subprogram "live_func" (rnglistx 0, has children)
	.byte	2
	.byte	0                               # DW_AT_ranges: rnglistx index 0
	.byte	2                               # DW_AT_name: strx1 index 2 -> "live_func"

	# Abbrev 5: DW_TAG_variable "v" (loclistx 0)
	.byte	5
	.byte	0                               # DW_AT_location: loclistx index 0

	.byte	0                               # End of live_func children

	# Abbrev 2: DW_TAG_subprogram "dead_func" (rnglistx 1, has children)
	.byte	2
	.byte	1                               # DW_AT_ranges: rnglistx index 1
	.byte	3                               # DW_AT_name: strx1 index 3 -> "dead_func"

	# Abbrev 5: DW_TAG_variable "w" (loclistx 1)
	.byte	5
	.byte	1                               # DW_AT_location: loclistx index 1

	.byte	0                               # End of dead_func children

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_cu_end:

	# --- Type unit ---
.Ldebug_info_tu_header:
	.long	.Ldebug_info_tu_end-.Ldebug_info_tu_start # Length of Unit
.Ldebug_info_tu_start:
	.short	5                               # DWARF version number
	.byte	6                               # DW_UT_split_type
	.byte	8                               # Address Size
	.long	0                               # Offset Into Abbrev. Section
	.quad	0x1234                          # Type signature
	.long	.Ltu_type_die-.Ldebug_info_tu_header # Type DIE offset (from unit start)

	# Abbrev 3: DW_TAG_type_unit (has children)
	.byte	3

.Ltu_type_die:
	# Abbrev 4: DW_TAG_base_type "int"
	.byte	4
	.byte	4                               # DW_AT_name: strx1 index 4 -> "int"

	.byte	0                               # End Of Children Mark (type_unit)
.Ldebug_info_tu_end:

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
	.long	.Lstr_offsets_end-.Lstr_offsets_start # Unit length
.Lstr_offsets_start:
	.short	5                               # Version
	.short	0                               # Padding
	.long	.Lstr0-.debug_str.dwo           # Index 0: "test.c"
	.long	.Lstr1-.debug_str.dwo           # Index 1: "/home"
	.long	.Lstr2-.debug_str.dwo           # Index 2: "live_func"
	.long	.Lstr3-.debug_str.dwo           # Index 3: "dead_func"
	.long	.Lstr4-.debug_str.dwo           # Index 4: "int"
.Lstr_offsets_end:

	.section	.debug_rnglists.dwo,"e",@progbits
.Lrnglists_section_start:
	.long	.Lrnglists_end-.Lrnglists_start # Unit length
.Lrnglists_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
	.long	2                               # Offset entry count
.Lrnglists_table_base:
	.long	.Lrangelist0-.Lrnglists_table_base  # Offset of range list 0
	.long	.Lrangelist1-.Lrnglists_table_base  # Offset of range list 1
.Lrangelist0:
	# Range list 0 (live_func): DW_RLE_startx_length addrx 0 (live), length 0x20
	.byte	0x03                            # DW_RLE_startx_length
	.byte	0                               # Start address index (ULEB128): addrx 0
	.byte	0x20                            # Length (ULEB128): 32 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrangelist1:
	# Range list 1 (dead_func): DW_RLE_startx_length addrx 1 (tombstoned), length 0x10
	.byte	0x03                            # DW_RLE_startx_length
	.byte	1                               # Start address index (ULEB128): addrx 1
	.byte	0x10                            # Length (ULEB128): 16 bytes
	.byte	0x00                            # DW_RLE_end_of_list
.Lrnglists_end:

	.section	.debug_loclists.dwo,"e",@progbits
.Lloclists_section_start:
	.long	.Lloclists_end-.Lloclists_start # Unit length
.Lloclists_start:
	.short	5                               # Version
	.byte	8                               # Address size
	.byte	0                               # Segment selector size
	.long	2                               # Offset entry count
.Lloclists_table_base:
	.long	.Lloclist0-.Lloclists_table_base    # Offset of location list 0
	.long	.Lloclist1-.Lloclists_table_base    # Offset of location list 1
.Lloclist0:
	# Location list 0 (v in live_func): DW_LLE_default_location with DW_OP_reg0
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x50                            # DW_OP_reg0
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclist1:
	# Location list 1 (w in dead_func): DW_LLE_default_location with DW_OP_reg1
	.byte	0x05                            # DW_LLE_default_location
	.byte	1                               # Expression length (ULEB128): 1 byte
	.byte	0x51                            # DW_OP_reg1
	.byte	0x00                            # DW_LLE_end_of_list
.Lloclists_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children,
	#           DW_AT_name(strx1) + DW_AT_comp_dir(strx1) +
	#           DW_AT_rnglists_base(sec_offset) + DW_AT_loclists_base(sec_offset)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0x1b                            # DW_AT_comp_dir
	.byte	0x25                            # DW_FORM_strx1
	.byte	0x74                            # DW_AT_rnglists_base
	.byte	23                              # DW_FORM_sec_offset
	.byte	0x8c, 0x01                      # DW_AT_loclists_base (ULEB128: 140)
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, has children,
	#           DW_AT_ranges(rnglistx) + DW_AT_name(strx1)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	0x55                            # DW_AT_ranges
	.byte	0x23                            # DW_FORM_rnglistx
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_type_unit, has children (no attributes)
	.byte	3                               # Abbreviation Code
	.byte	0x41                            # DW_TAG_type_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 4: DW_TAG_base_type, no children,
	#           DW_AT_name(strx1)
	.byte	4                               # Abbreviation Code
	.byte	0x24                            # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	0x25                            # DW_FORM_strx1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 5: DW_TAG_variable, no children,
	#           DW_AT_location(loclistx)
	.byte	5                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	0x22                            # DW_FORM_loclistx
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
