# Fake executable for gc-ranges-dead-v4.test
#
# DWARF4 skeleton CU (GNU extension) containing:
#   .debug_info:   DW_TAG_compile_unit with DW_AT_GNU_dwo_id = 0xdd,
#                  DW_AT_GNU_addr_base, and DW_AT_GNU_dwo_name
#   .debug_addr:   One 8-byte address (no header, DWARF4 style):
#                    index 0: 0x1000 (live, live_func)
#   .debug_ranges: Three range lists used by subprograms in the .dwo:
#                    offset 0x00: dead_func (all entries use tombstoned addresses)
#                    offset 0x20: dead_base_func (base address tombstoned + offset pair)
#                    offset 0x50: mixed_func (one tombstoned + one live entry)
#   .debug_abbrev: abbreviation table for the skeleton CU

	.section	.debug_info,"",@progbits
	.long	.Ldebug_info_end-.Ldebug_info_start # Length of Unit
.Ldebug_info_start:
	.short	4                               # DWARF version number
	.long	0                               # Offset Into Abbrev. Section
	.byte	8                               # Address Size

	# [0x0b] Abbrev 1: DW_TAG_compile_unit
	.byte	1
	.quad	0xdd                            # DW_AT_GNU_dwo_id
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

	.section	.debug_ranges,"",@progbits
	# DWARF4 .debug_ranges: pairs of (start, end) addresses, 8 bytes each.
	# (0xffffffffffffffff, addr) = base address selector.
	# (0, 0) = end of list.

	# --- Range list 0 at offset 0x00: dead_func (all entries tombstoned) ---
	# Single range with GNU ld tombstoned start address (0x0).
	.quad	0x0                             # Start: 0 (GNU ld tombstone)
	.quad	0x10                            # End
	.quad	0x0                             # End of list
	.quad	0x0                             # End of list

	# --- Range list 1 at offset 0x20: dead_base_func (base tombstoned) ---
	# Base address selector: set base to 0 (GNU ld tombstone).
	.quad	0xffffffffffffffff              # Base address selector sentinel
	.quad	0x0                             # New base: 0 (GNU ld tombstone)
	# Offset pair under the tombstoned base.
	.quad	0x0                             # Start offset
	.quad	0x20                            # End offset
	# End of list.
	.quad	0x0
	.quad	0x0

	# --- Range list 2 at offset 0x50: mixed_func (one dead + one live) ---
	# Entry 1: tombstoned.
	.quad	0x0                             # Start: 0 (GNU ld tombstone)
	.quad	0x10                            # End
	# Entry 2: live.
	.quad	0x2000                          # Start: live address
	.quad	0x2010                          # End
	# End of list.
	.quad	0x0
	.quad	0x0
