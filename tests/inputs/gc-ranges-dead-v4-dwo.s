# .dwo file for gc-ranges-dead-v4.test
#
# DWARF4 split-compile unit (GNU extension) containing:
#   compile_unit (children, DW_AT_GNU_dwo_id = 0xdd)
#     subprogram "dead_func": DW_AT_ranges = sec_offset 0x00 (all entries tombstoned)
#     subprogram "dead_base_func": DW_AT_ranges = sec_offset 0x20 (base tombstoned + offset pair)
#     subprogram "mixed_func": DW_AT_ranges = sec_offset 0x50 (one tombstoned + one live)
#     subprogram "live_func": DW_AT_low_pc = GNU_addr_index 0 (live)
#
# These sec_offsets are relative to the skeleton's DW_AT_GNU_ranges_base; the absolute
# offsets into the executable's .debug_ranges are ranges_base (0x40) plus these values.
#
# The range data lives in the skeleton executable's .debug_ranges section,
# not in a .dwo section (DWARF4 has no .debug_ranges.dwo).
#
# DWO ID is 0xdd.

	.section	.debug_info.dwo,"e",@progbits
	.long	.Ldebug_info_dwo_end-.Ldebug_info_dwo_start # Length of Unit
.Ldebug_info_dwo_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size

	# Abbrev 1: DW_TAG_compile_unit (has children)
	.byte	1
	.quad	0xdd                            # DW_AT_GNU_dwo_id

	# Abbrev 2: DW_TAG_subprogram "dead_func" (DW_AT_ranges = sec_offset 0x00)
	.byte	2
	.long	0x00                            # DW_AT_ranges: sec_offset into .debug_ranges
	.asciz	"dead_func"                     # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "dead_base_func" (DW_AT_ranges = sec_offset 0x20)
	.byte	2
	.long	0x20                            # DW_AT_ranges: sec_offset into .debug_ranges
	.asciz	"dead_base_func"                # DW_AT_name

	# Abbrev 2: DW_TAG_subprogram "mixed_func" (DW_AT_ranges = sec_offset 0x50)
	.byte	2
	.long	0x50                            # DW_AT_ranges: sec_offset into .debug_ranges
	.asciz	"mixed_func"                    # DW_AT_name

	# Abbrev 3: DW_TAG_subprogram "live_func" (DW_AT_low_pc = GNU_addr_index 0)
	.byte	3
	.byte	0                               # DW_AT_low_pc: GNU_addr_index index 0
	.asciz	"live_func"                     # DW_AT_name

	.byte	0                               # End Of Children Mark (compile_unit)
.Ldebug_info_dwo_end:

	.section	.debug_abbrev.dwo,"e",@progbits
	# Abbrev 1: DW_TAG_compile_unit, has children, DW_AT_GNU_dwo_id(data8)
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.uleb128	0x2131                  # DW_AT_GNU_dwo_id
	.uleb128	7                       # DW_FORM_data8
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 2: DW_TAG_subprogram, no children, DW_AT_ranges(sec_offset) + DW_AT_name(string)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	0x55                            # DW_AT_ranges
	.byte	23                              # DW_FORM_sec_offset
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	# Abbrev 3: DW_TAG_subprogram, no children, DW_AT_low_pc(GNU_addr_index) + DW_AT_name(string)
	.byte	3                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.uleb128	0x1f01                  # DW_FORM_GNU_addr_index
	.byte	3                               # DW_AT_name
	.byte	8                               # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)

	.byte	0                               # End of abbreviations
