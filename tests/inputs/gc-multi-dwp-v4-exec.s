# Fake executable for gc-multi-dwp-v4.test (DWARF4 GNU extension).
#
# Provides garbage-collection address data for two compilation units that are
# re-packaged from a multi-CU `.dwp` input:
#   DWO ID 0xdd (from gc-loclist-v4-dwo.s)
#   DWO ID 0xde (from gc-multi-dwp-v4-b-dwo.s)
#
# Each skeleton CU has its own DW_AT_GNU_addr_base into a per-CU address table.
# The `.dwo` references are never loaded: the `.dwp` is processed first, so the
# units are already contained and the executable only contributes addr data.
#
# Both address tables: index 0 tombstone, index 1 live, index 2 tombstone.

	.section	.debug_info,"",@progbits
	# Skeleton CU for DWO ID 0xdd
	.long	.Ldebug_info_dd_end-.Ldebug_info_dd_start # Length of Unit
.Ldebug_info_dd_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size
	.byte	1                               # Abbrev 1: DW_TAG_compile_unit
	.quad	0xdd                            # DW_AT_GNU_dwo_id
	.long	.Laddr_table_dd                 # DW_AT_GNU_addr_base
	.asciz	"ignored-dd.dwo"                # DW_AT_GNU_dwo_name (never loaded)
.Ldebug_info_dd_end:

	# Skeleton CU for DWO ID 0xde
	.long	.Ldebug_info_de_end-.Ldebug_info_de_start # Length of Unit
.Ldebug_info_de_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size
	.byte	1                               # Abbrev 1: DW_TAG_compile_unit
	.quad	0xde                            # DW_AT_GNU_dwo_id
	.long	.Laddr_table_de                 # DW_AT_GNU_addr_base
	.asciz	"ignored-de.dwo"                # DW_AT_GNU_dwo_name (never loaded)
.Ldebug_info_de_end:

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
.Laddr_table_dd:
	.quad	0xffffffffffffffff              # Index 0: tombstone
	.quad	0x1000                          # Index 1: live
	.quad	0xffffffffffffffff              # Index 2: tombstone
.Laddr_table_de:
	.quad	0xffffffffffffffff              # Index 0: tombstone
	.quad	0x1000                          # Index 1: live
	.quad	0xffffffffffffffff              # Index 2: tombstone
