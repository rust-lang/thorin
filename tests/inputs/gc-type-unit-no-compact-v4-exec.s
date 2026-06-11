# Fake executable for gc-type-unit-no-compact-v4.test
#
# DWARF4 skeleton CU (GNU extension) containing:
#   .debug_info:   DW_TAG_compile_unit with DW_AT_GNU_dwo_id = 0xee,
#                  DW_AT_GNU_addr_base, and DW_AT_GNU_dwo_name
#   .debug_addr:   Two 8-byte addresses (no header, DWARF4 style):
#                    index 0: 0x1000             (live, live_func)
#                    index 1: 0xffffffffffffffff (tombstone, dead_func)
#   .debug_abbrev: abbreviation table for the skeleton CU

	.section	.debug_info,"",@progbits
	.long	.Ldebug_info_end-.Ldebug_info_start # Length of Unit
.Ldebug_info_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size

	# [0x0b] Abbrev 1: DW_TAG_compile_unit
	.byte	1
	.quad	0xee                            # DW_AT_GNU_dwo_id
	.long	.Laddr_table_base               # DW_AT_GNU_addr_base
	.asciz	"DWO_PATH"                      # DW_AT_GNU_dwo_name (substituted by sed)
.Ldebug_info_end:

	.section	.debug_abbrev,"",@progbits
	# Abbrev 1: DW_TAG_compile_unit, no children
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	0                               # DW_CHILDREN_no
	.uleb128	0x2131                  # DW_AT_GNU_dwo_id
	.uleb128	7                       # DW_FORM_data8
	.uleb128	0x2133                  # DW_AT_GNU_addr_base
	.uleb128	23                      # DW_FORM_sec_offset
	.uleb128	0x2130                  # DW_AT_GNU_dwo_name
	.uleb128	8                       # DW_FORM_string
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	0                               # End of abbreviations

	.section	.debug_addr,"",@progbits
	# DWARF4: no header, just raw address entries.
	# DW_AT_GNU_addr_base points directly to the start of entries.
.Laddr_table_base:
	.quad	0x1000                          # Index 0: live address (live_func)
	.quad	0xffffffffffffffff              # Index 1: tombstone (dead_func)
