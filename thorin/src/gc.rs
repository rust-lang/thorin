//! Garbage Collection pass for DWARF package files.
//!
//! The basic idea is that we identify certain DIEs in the .debug_info.dwo
//! section as roots, mark and sweep the graph of DIEs, and then rewrite
//! other supporting sections including .debug_loclists.dwo,
//! .debug_rnglists.dwo, and .debug_str_offsets.dwo to drop now unneeded
//! data. We also need to rewrite the debug locations data for correctness
//! as a location expression could in theory refer back to the
//! .debug_info.dwo section.
//!
//! We do not attempt to examine type units (and thus disable dropping data
//! from the supporting sections in their presence). We also disable rewriting
//! .debug_str_offsets if a .debug_macro section is present, since we do not
//! attempt to examine .debug_macro and it can reference strings. Finally,
//! in the DWARF 4 variant of split DWARF, we do not attempt to shrink the
//! supporting .debug_locs/.debug_ranges sections.

// gimli's `DW_FORM_*` / `DW_OP_*` constants are not upper-case; matching them in patterns would
// otherwise trigger `non_upper_case_globals` throughout this module.
#![allow(non_upper_case_globals)]

use gimli::write::{EndianVec, Writer};
use gimli::{DebugAddrIndex, Reader, RunTimeEndian, Section};
use hashbrown::HashMap;
use itertools::izip;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use tracing::{debug, trace, warn};

use crate::{
    error::{Error, Result},
    package::DwoId,
    relocate::Relocate,
};

/// Result of garbage-collecting a `.debug_info.dwo` compilation unit.
pub(crate) struct GcResult {
    /// Rewritten `.debug_info.dwo` bytes, or `None` if nothing was removed.
    pub rewritten: Option<EndianVec<RunTimeEndian>>,
    /// Map from old DIE offsets to new offsets after dead DIEs were removed
    /// and their level in the DIE tree.
    /// Present only when `rewritten` is `Some`. Used to patch CU-relative references
    /// embedded in location list expressions.
    pub offset_remap: Option<BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>>,
    /// `rnglistx` index values referenced by surviving DIEs, or `None` if the section
    /// cannot be safely pruned (e.g. a DIE used `DW_FORM_sec_offset` for `DW_AT_ranges`).
    pub referenced_rnglists: Option<BTreeSet<u64>>,
    /// `loclistx` index values referenced by surviving DIEs, or `None` if the section
    /// cannot be safely pruned (e.g. a DIE used `DW_FORM_sec_offset` for `DW_AT_location`).
    pub referenced_loclists: Option<BTreeSet<u64>>,
    /// `strx` index values referenced by surviving DIEs, or `None` if the section
    /// cannot be safely pruned (e.g. a `.debug_macro` section is present).
    pub referenced_str_offsets: Option<BTreeSet<u64>>,
}

/// Returns `true` if the given address is a tombstone value.
pub(crate) fn is_tombstone(addr: u64, address_size: u8) -> bool {
    let negative_one = match address_size {
        4 => 0xffff_ffff_u64,
        8 => 0xffff_ffff_ffff_ffff_u64,
        _ => return false,
    };
    // GNU ld uses 0 as a tombstone, lld/mold use -1.
    addr == 0 || addr == negative_one
}

/// Serialize a `gimli::RawRngListEntry` back into bytes.
///
/// gimli provides a parser (`RangeLists::raw_ranges`) but no writer for `.debug_rnglists`, so we
/// re-encode each surviving entry here. `DW_RLE_end_of_list` is emitted by the caller.
fn encode_raw_rng_entry(
    entry: &gimli::RawRngListEntry<usize>,
    out: &mut EndianVec<RunTimeEndian>,
    address_size: u8,
) -> Result<()> {
    use gimli::constants::*;
    match *entry {
        gimli::RawRngListEntry::BaseAddressx { addr } => {
            out.write_u8(DW_RLE_base_addressx.0)?;
            out.write_uleb128(addr.0 as u64)?;
        }
        gimli::RawRngListEntry::StartxEndx { begin, end } => {
            out.write_u8(DW_RLE_startx_endx.0)?;
            out.write_uleb128(begin.0 as u64)?;
            out.write_uleb128(end.0 as u64)?;
        }
        gimli::RawRngListEntry::StartxLength { begin, length } => {
            out.write_u8(DW_RLE_startx_length.0)?;
            out.write_uleb128(begin.0 as u64)?;
            out.write_uleb128(length)?;
        }
        gimli::RawRngListEntry::OffsetPair { begin, end }
        | gimli::RawRngListEntry::AddressOrOffsetPair { begin, end } => {
            out.write_u8(DW_RLE_offset_pair.0)?;
            out.write_uleb128(begin)?;
            out.write_uleb128(end)?;
        }
        gimli::RawRngListEntry::BaseAddress { addr } => {
            out.write_u8(DW_RLE_base_address.0)?;
            out.write_udata(addr, address_size)?;
        }
        gimli::RawRngListEntry::StartEnd { begin, end } => {
            out.write_u8(DW_RLE_start_end.0)?;
            out.write_udata(begin, address_size)?;
            out.write_udata(end, address_size)?;
        }
        gimli::RawRngListEntry::StartLength { begin, length } => {
            out.write_u8(DW_RLE_start_length.0)?;
            out.write_udata(begin, address_size)?;
            out.write_uleb128(length)?;
        }
    }

    Ok(())
}

/// Reassemble a `.debug_rnglists.dwo` or `.debug_loclists.dwo` section from
/// pre-encoded list bodies. Writes the unit header, offset table, and list data.
fn reassemble_offset_table_section(
    encoded_lists: &[Vec<u8>],
    header: &gimli::ListsHeader,
    endian: RunTimeEndian,
) -> Result<Vec<u8>> {
    let encoding = header.encoding;
    let word_size = encoding.format.word_size() as usize;
    let new_entry_count = encoded_lists.len() as u32;
    let new_offset_array_size = new_entry_count as usize * word_size;

    let mut new_offsets: Vec<u64> = Vec::with_capacity(encoded_lists.len());
    let mut running_offset: u64 = new_offset_array_size as u64;
    for enc in encoded_lists {
        new_offsets.push(running_offset);
        running_offset += enc.len() as u64;
    }
    let total_entries_size = running_offset - new_offset_array_size as u64;

    let initial_length_size = encoding.format.initial_length_size() as u64;
    let new_unit_length: u64 = header.size() as u64 - initial_length_size
        + (new_entry_count as u64 * word_size as u64)
        + total_entries_size;

    let mut out = EndianVec::new(endian);

    if encoding.format == gimli::Format::Dwarf64 {
        out.write_u32(0xffff_ffff)?;
        out.write_u64(new_unit_length)?;
    } else {
        out.write_u32(
            new_unit_length.try_into().expect("unit length w/out header larger than u32"),
        )?;
    }

    out.write_u16(encoding.version)?;
    out.write_u8(encoding.address_size)?;
    out.write_u8(0)?;
    out.write_u32(new_entry_count)?;

    for &off in &new_offsets {
        if encoding.format == gimli::Format::Dwarf64 {
            out.write_u64(off)?;
        } else {
            out.write_u32(off.try_into().expect("offset larger than u32"))?;
        }
    }

    for enc in encoded_lists {
        out.write(enc)?;
    }

    Ok(out.into_vec())
}

/// Rewrite a `.debug_rnglists.dwo` section: remove tombstoned entries and replace
/// unreferenced range lists with empty ones.
///
/// Returns `None` if nothing changed (caller should use the original data).
/// Returns `Some(vec)` with the new section bytes if anything was modified.
pub(crate) fn rewrite_rnglists<IsAddrLive>(
    data: gimli::EndianSlice<'_, RunTimeEndian>,
    referenced_indices: &BTreeSet<u64>,
    is_addr_live: &IsAddrLive,
    dwo_id: DwoId,
) -> Result<Option<Vec<u8>>>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    if data.is_empty() {
        return Ok(None);
    }
    let endian = data.endian();

    // Parse the header.
    let mut input = data;
    let header = gimli::ListsHeader::parse(&mut input)?;
    let encoding = header.encoding;
    let offset_entry_count = header.offset_entry_count;
    let address_size = encoding.address_size;

    let header_size = header.size() as usize;

    let debug_rnglists = gimli::DebugRngLists::from(data);
    let debug_ranges = gimli::DebugRanges::from(gimli::EndianSlice::new(&[][..], endian));
    let range_lists = gimli::RangeLists::new(debug_ranges, debug_rnglists);
    let base = gimli::DebugRngListsBase(header_size);

    // Parse each range list in turn.
    struct ParsedList(Vec<gimli::RawRngListEntry<usize>>);
    let mut parsed_lists: Vec<ParsedList> = Vec::with_capacity(offset_entry_count as usize);
    let mut modified_count = 0;

    for list_idx in 0..offset_entry_count as usize {
        if !referenced_indices.contains(&(list_idx as u64)) {
            trace!(list_idx, "removing unreferenced range list");
            continue;
        }

        let offset = range_lists.get_offset(encoding, base, gimli::DebugRngListsIndex(list_idx))?;

        let mut entries: Vec<gimli::RawRngListEntry<usize>> = Vec::new();
        let mut base_tombstoned = false;
        let mut any_removed = false;

        let mut raw_iter = range_lists.raw_ranges(offset, encoding)?;

        while let Some(entry) = raw_iter.next()? {
            match entry {
                gimli::RawRngListEntry::BaseAddressx { addr } => {
                    if !is_addr_live(addr)? {
                        base_tombstoned = true;
                        any_removed = true;
                        trace!(list_idx, "removing tombstoned base_addressx idx={}", addr.0);
                    } else {
                        base_tombstoned = false;
                        entries.push(entry);
                    }
                }
                gimli::RawRngListEntry::BaseAddress { addr } => {
                    if is_tombstone(addr, address_size) {
                        base_tombstoned = true;
                        any_removed = true;
                        trace!(list_idx, "removing tombstoned base_address addr={:#x}", addr);
                    } else {
                        base_tombstoned = false;
                        entries.push(entry);
                    }
                }
                gimli::RawRngListEntry::OffsetPair { .. }
                | gimli::RawRngListEntry::AddressOrOffsetPair { .. } => {
                    if base_tombstoned {
                        any_removed = true;
                        trace!(list_idx, "removing offset_pair under tombstoned base");
                    } else {
                        entries.push(entry);
                    }
                }
                gimli::RawRngListEntry::StartxEndx { begin, .. } => {
                    if !is_addr_live(begin)? {
                        any_removed = true;
                        trace!(list_idx, "removing tombstoned startx_endx");
                    } else {
                        entries.push(entry);
                    }
                }
                gimli::RawRngListEntry::StartxLength { begin, .. } => {
                    if !is_addr_live(begin)? {
                        any_removed = true;
                        trace!(list_idx, "removing tombstoned startx_length");
                    } else {
                        entries.push(entry);
                    }
                }
                gimli::RawRngListEntry::StartEnd { begin, .. } => {
                    if is_tombstone(begin, address_size) {
                        any_removed = true;
                        trace!(list_idx, "removing tombstoned start_end");
                    } else {
                        entries.push(entry);
                    }
                }
                gimli::RawRngListEntry::StartLength { begin, .. } => {
                    if is_tombstone(begin, address_size) {
                        any_removed = true;
                        trace!(list_idx, "removing tombstoned start_length");
                    } else {
                        entries.push(entry);
                    }
                }
            }
        }

        if any_removed {
            modified_count += 1;
        }

        parsed_lists.push(ParsedList(entries));
    }

    let new_entry_count = parsed_lists.len() as u32;
    let lists_removed = offset_entry_count - new_entry_count;

    // If no list was modified and no lists were dropped, return None (no change).
    if modified_count == 0 && lists_removed == 0 {
        return Ok(None);
    }

    debug!(
        ?dwo_id,
        lists_removed,
        modified_count,
        total = offset_entry_count,
        remaining = new_entry_count,
        "rewrite_rnglists: pruned range lists"
    );

    // Reassemble surviving range lists.
    let mut encoded_lists: Vec<Vec<u8>> = Vec::with_capacity(parsed_lists.len());
    for list in &parsed_lists {
        let mut buf = EndianVec::new(endian);
        for entry in &list.0 {
            encode_raw_rng_entry(entry, &mut buf, address_size)?;
        }
        buf.write_u8(gimli::constants::DW_RLE_end_of_list.0)?;
        encoded_lists.push(buf.into_vec());
    }

    Ok(Some(reassemble_offset_table_section(&encoded_lists, &header, endian)?))
}

/// Patch CU-relative references in DWARF expressions within a `.debug_loc.dwo` section.
/// We do not attempt to remove unused location lists.
///
/// DWARF4 split DWARF encodes location lists in `.debug_loc.dwo` using DW_LLE entry types
/// (GNU extension). The section has no header — it is a flat stream of DW_LLE entries.
///
/// Returns `None` if nothing changed (caller should use the original data).
/// Returns `Some(vec)` with the patched section bytes if any expression was patched.
pub(crate) fn patch_debug_loc(
    data: gimli::EndianSlice<'_, RunTimeEndian>,
    encoding: gimli::Encoding,
    offset_remap: &BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>,
) -> Result<Option<Vec<u8>>> {
    let raw = data.slice();
    if raw.is_empty() {
        return Ok(None);
    }
    let endian = data.endian();

    let mut patched = raw.to_vec();
    let any_patched = patch_loclist_data(raw, endian, encoding, offset_remap, &mut patched)?;
    if any_patched {
        Ok(Some(patched))
    } else {
        Ok(None)
    }
}

/// Rewrite a `.debug_loclists.dwo` section: remove unreferenced location lists and/or
/// patch CU-relative references in DWARF expressions embedded in location list entries.
///
/// `referenced_indices` controls pruning. Only lists whose index is in this set
/// are retained. If `referenced_indices` is None, all lists are assumed to be referenced.
///
/// `offset_remap` controls expression patching: when `Some`, CU-relative references
/// (e.g. `DW_OP_call4`) are updated to reflect new DIE offsets after GC.
///
/// Returns `None` if nothing changed (caller should use the original data).
/// Returns `Some(vec)` with the new section bytes if anything was pruned or patched.
pub(crate) fn rewrite_loclists(
    data: gimli::EndianSlice<'_, RunTimeEndian>,
    referenced_indices: Option<&BTreeSet<u64>>,
    offset_remap: Option<&BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>>,
) -> Result<Option<Vec<u8>>> {
    if data.is_empty() {
        return Ok(None);
    }
    let endian = data.endian();

    // Parse the header.
    let mut input = data;
    let header = gimli::ListsHeader::parse(&mut input)?;
    let encoding = header.encoding;
    let offset_entry_count = header.offset_entry_count;
    let header_size = header.size() as usize;
    let debug_loclists = gimli::DebugLocLists::from(data);
    let debug_loc = gimli::DebugLoc::from(gimli::EndianSlice::new(&[][..], endian));
    let loc_lists = gimli::LocationLists::new(debug_loc, debug_loclists);

    let raw = data.slice();

    // When offset_entry_count == 0 (which is permitted by the DWARF 5 spec, as long
    // as DW_FORM_sec_offset is used), there is no offset table to iterate.
    // We can't prune individual lists, but we still need to patch CU-relative
    // references in expressions.
    if offset_entry_count == 0 {
        if let Some(remap) = offset_remap {
            let entry_data = &raw[header_size..];
            let mut patched = raw.to_vec();
            let did_patch = patch_loclist_data(
                entry_data,
                endian,
                encoding,
                remap,
                &mut patched[header_size..],
            )?;
            if did_patch {
                return Ok(Some(patched));
            }
        }
        return Ok(None);
    }

    let base = gimli::DebugLocListsBase(header_size);

    // Resolve all offsets and determine byte spans for each list. Lists in the
    // offset table are not necessarily contiguous or ordered, so we sort the
    // start offsets to derive each list's extent.
    let mut abs_offsets: Vec<usize> = Vec::with_capacity(offset_entry_count as usize);
    for list_idx in 0..offset_entry_count as usize {
        let offset = loc_lists.get_offset(encoding, base, gimli::DebugLocListsIndex(list_idx))?;
        abs_offsets.push(offset.0);
    }

    // Build a sorted list of (abs_offset, list_idx) to determine end boundaries.
    let mut sorted: Vec<(usize, u32)> =
        abs_offsets.iter().enumerate().map(|(i, &off)| (off, i as u32)).collect();
    sorted.sort_unstable();

    // Map from list_idx -> byte length of that list in the original section.
    let mut list_lengths: Vec<usize> = vec![0; offset_entry_count as usize];
    for (i, &(start, idx)) in sorted.iter().enumerate() {
        let end = if i + 1 < sorted.len() { sorted[i + 1].0 } else { raw.len() };
        list_lengths[idx as usize] = end - start;
    }

    // Reassemble surviving loclists.
    let mut encoded_lists: Vec<Vec<u8>> =
        Vec::with_capacity(referenced_indices.map_or(offset_entry_count as usize, |s| s.len()));
    let mut pruned_count: u32 = 0;
    let mut any_patched = false;

    for list_idx in 0..offset_entry_count as usize {
        let keep = referenced_indices.is_none_or(|set| set.contains(&(list_idx as u64)));
        if keep {
            let start = abs_offsets[list_idx];
            let len = list_lengths[list_idx];
            let list_bytes = &raw[start..start + len];

            if let Some(remap) = offset_remap {
                let mut patched = list_bytes.to_vec();
                let did_patch =
                    patch_loclist_data(list_bytes, endian, encoding, remap, &mut patched)?;
                any_patched |= did_patch;
                encoded_lists.push(patched);
            } else {
                encoded_lists.push(list_bytes.to_vec());
            }
        } else {
            pruned_count += 1;
            trace!(list_idx, "removing unreferenced location list");
        }
    }

    if pruned_count == 0 && !any_patched {
        return Ok(None);
    }

    if pruned_count > 0 {
        debug!(
            pruned_count,
            total = offset_entry_count,
            remaining = encoded_lists.len(),
            "rewrite_loclists: pruned location lists"
        );
    }

    Ok(Some(reassemble_offset_table_section(&encoded_lists, &header, endian)?))
}

/// Patch CU-relative references in DWARF expressions within location list entries.
///
/// `raw` is the byte slice containing the loclist entries to scan (no header or offset
/// table — just the entry data). `patched` is a mutable copy where patched bytes are
/// written; it must have the same length as `raw`.
///
/// Returns `true` if any expression was patched.
fn patch_loclist_data(
    raw: &[u8],
    endian: RunTimeEndian,
    encoding: gimli::Encoding,
    offset_remap: &BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>,
    patched: &mut [u8],
) -> Result<bool> {
    use gimli::constants::*;
    assert_eq!(raw.len(), patched.len());

    let mut any_patched = false;
    let mut reader = gimli::EndianSlice::new(raw, endian);
    let address_size = encoding.address_size;

    while !reader.is_empty() {
        let entry_type = reader.read_u8()?;

        let has_expr = match DwLle(entry_type) {
            DW_LLE_end_of_list => false,
            DW_LLE_base_addressx => {
                reader.read_uleb128()?;
                false
            }
            DW_LLE_startx_endx => {
                reader.read_uleb128()?;
                reader.read_uleb128()?;
                true
            }
            DW_LLE_startx_length => {
                reader.read_uleb128()?;
                if encoding.version >= 5 {
                    reader.read_uleb128()?;
                } else {
                    reader.read_u32()?;
                }
                true
            }
            DW_LLE_offset_pair => {
                reader.read_uleb128()?;
                reader.read_uleb128()?;
                true
            }
            DW_LLE_default_location => true,
            DW_LLE_base_address => {
                reader.read_address(address_size)?;
                false
            }
            DW_LLE_start_end => {
                reader.read_address(address_size)?;
                reader.read_address(address_size)?;
                true
            }
            DW_LLE_start_length => {
                reader.read_address(address_size)?;
                reader.read_uleb128()?;
                true
            }
            x => return Err(Error::UnsupportedLocListsEntry(x.0)),
        };

        // NB: Because `patched` is initialized by the caller with `raw`,
        // we only have to act if we change something.
        if has_expr {
            let expr_len = if encoding.version >= 5 {
                reader.read_uleb128()? as usize
            } else {
                reader.read_u16()? as usize
            };
            let expr_slice = reader.split(expr_len)?;

            let mut out = EndianVec::new(endian);
            emit_expression(expr_slice, offset_remap, encoding, &mut out)?;

            if out.slice() != expr_slice.slice() {
                let expr_offset = raw.len() - reader.len() - expr_len;
                patched[expr_offset..expr_offset + expr_len].copy_from_slice(out.slice());
                any_patched = true;
            }
        }
    }

    Ok(any_patched)
}

/// Liveness state of a DIE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Liveness {
    /// Removed from output.
    Dead,
    /// The DIE, all of its descendants, and everything it references survive.
    Live,
    /// This DIE must survive to maintain the tree structure (i.e. it is the ancestor
    /// of a Live DIE). We keep everything its attributes reference to avoid
    /// dangling, but it does *not* keep its descendants alive.
    Retained,
}

/// A parsed DIE record from the analysis pass.
///
/// Byte offsets and tags are re-derived from the raw byte stream during the
/// rewrite pass, so they are not stored here — only the grap edges and liveness
/// state needed by the mark-and-sweep are retained.
struct DieRecord {
    /// Index of the parent DIE record, if any.
    parent: Option<usize>,
    /// Children of the current DIE record, if any.
    children: Vec<usize>,
    /// Edges from the attributes of this DIE to other DIEs. Because these can
    /// be forward looking we can't resolve them into DIE indexes at this stage.
    edges: Vec<gimli::UnitOffset>,
    /// Current liveness state.
    liveness: Liveness,
}

/// Write an unsigned LEB128 value padded to exactly `width` bytes.
///
/// ULEB128 allows redundant high zero bytes; we exploit this to keep the encoded length stable
/// when patching offsets (which only ever shrink).  See the comment on [`rewrite_unit`] for why
/// we use this byte-stable strategy rather than re-encoding at the natural (shorter) width.
fn write_uleb128_padded(
    out: &mut EndianVec<RunTimeEndian>,
    value: gimli::UnitOffset,
    width: usize,
) -> Result<()> {
    // Number of bytes the natural encoding requires.
    let mut tmp = value.0;
    let mut natural = 0usize;
    loop {
        natural += 1;
        tmp >>= 7;
        if tmp == 0 {
            break;
        }
    }
    assert!(natural <= width);
    let mut v = value.0;
    for i in 0..width {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        // All but the last byte get the continuation bit.
        if i + 1 < width {
            byte |= 0x80;
        }
        out.write_u8(byte)?;
    }
    Ok(())
}

/// Number of bytes a ULEB128 value occupies starting at `pos`.
fn uleb128_len(mut data: gimli::EndianSlice<'_, RunTimeEndian>) -> Result<usize> {
    let before = data.len();
    data.read_uleb128()?;
    Ok(before - data.len())
}

/// A CU-relative DIE reference embedded in a DWARF expression, located at a byte offset within
/// the expression and encoded with the given operand layout (so it can be patched in place).
#[derive(Clone, Copy, Debug)]
struct ExprRef {
    /// Byte offset of the operand within the expression.
    pos: usize,
    /// Old CU-relative offset value.
    old: gimli::UnitOffset,
    /// Encoding of the operand.
    enc: ExprRefEnc,
}

/// Operand encoding of a CU-relative reference embedded in an expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExprRefEnc {
    /// 2-byte fixed (`DW_OP_call2`).
    U2,
    /// 4-byte fixed (`DW_OP_call4`, `DW_OP_GNU_parameter_ref`).
    U4,
    /// ULEB128 (`DW_OP_const_type`, `DW_OP_regval_type`, etc.).
    Uleb,
}

/// Walk a DWARF expression, invoking `on_ref` for each *CU-relative* DIE reference operation and
/// recording its byte position and encoding. Section-absolute references (`DW_OP_call_ref`,
/// `DW_OP_implicit_pointer`) are reported via `on_sec_ref` with their (section-absolute) value.
///
/// This advances through the expression using gimli's operation parser, then
/// for the handful of reference-bearing opcodes recomputes the operand's byte
/// position from the opcode's known operand layout so it can be patched in place.
///
/// Recurses into `DW_OP_entry_value` / `DW_OP_GNU_entry_value` sub-expressions; `base` is the
/// byte offset of `expr` within the enclosing buffer so positions are absolute to that buffer.
fn walk_expression<F, G>(
    expression: gimli::Expression<gimli::EndianSlice<'_, RunTimeEndian>>,
    base: usize,
    encoding: gimli::Encoding,
    on_ref: &mut F,
    on_sec_ref: &mut G,
) -> Result<()>
where
    F: FnMut(ExprRef),
    G: FnMut(usize),
{
    let mut iter = expression.operations(encoding);
    let mut start = 0;
    while let Some(op) = iter.next()? {
        let end = iter.offset_from(&expression);
        match op {
            gimli::Operation::Call { offset } => match offset {
                gimli::DieReference::UnitRef(unit_off) => {
                    // In order to get the size correct, we have to look at the opcode
                    // which gimli doesn't directly expose.
                    let (enc, opnd_pos) = match gimli::DwOp(expression.0.slice()[start]) {
                        gimli::constants::DW_OP_call2 => (ExprRefEnc::U2, start + 1),
                        gimli::constants::DW_OP_call4 => (ExprRefEnc::U4, start + 1),
                        _ => {
                            // Unexpected; treat conservatively as malformed.
                            return Err(Error::MalformedDebugInfo);
                        }
                    };
                    on_ref(ExprRef { pos: base + opnd_pos, old: unit_off, enc });
                }
                gimli::DieReference::DebugInfoRef(off) => {
                    // DW_OP_call_ref: section-absolute.
                    on_sec_ref(off.0);
                }
            },
            gimli::Operation::ImplicitPointer { value, .. } => {
                // DW_OP_implicit_pointer / GNU: section-absolute offset.
                on_sec_ref(value.0);
            }
            gimli::Operation::ParameterRef { offset } => {
                // DW_OP_GNU_parameter_ref: CU-relative, 4-byte.
                on_ref(ExprRef { pos: base + start + 1, old: offset, enc: ExprRefEnc::U4 });
            }
            gimli::Operation::TypedLiteral { base_type, .. } => {
                // DW_OP_const_type: ULEB128 CU-relative offset (operand 1).
                if base_type.0 != 0 {
                    on_ref(ExprRef {
                        pos: base + start + 1,
                        old: base_type,
                        enc: ExprRefEnc::Uleb,
                    });
                }
            }
            gimli::Operation::RegisterOffset { base_type, .. } => {
                // DW_OP_regval_type: ULEB128 register, then ULEB128 base_type offset.
                if base_type.0 != 0 {
                    let reg_len = uleb128_len(expression.0.range_from(start + 1..))?;
                    on_ref(ExprRef {
                        pos: base + start + 1 + reg_len,
                        old: base_type,
                        enc: ExprRefEnc::Uleb,
                    });
                }
            }
            gimli::Operation::Deref { base_type, .. } => {
                // DW_OP_deref_type / DW_OP_xderef_type: size byte, then ULEB128 base_type offset.
                // (Plain DW_OP_deref/xderef have base_type == 0.)
                if base_type.0 != 0 {
                    on_ref(ExprRef {
                        pos: base + start + 2,
                        old: base_type,
                        enc: ExprRefEnc::Uleb,
                    });
                }
            }
            gimli::Operation::Convert { base_type }
            | gimli::Operation::Reinterpret { base_type } => {
                // DW_OP_convert / DW_OP_reinterpret: ULEB128 CU-relative offset (0 == generic).
                if base_type.0 != 0 {
                    on_ref(ExprRef {
                        pos: base + start + 1,
                        old: base_type,
                        enc: ExprRefEnc::Uleb,
                    });
                }
            }
            gimli::Operation::EntryValue { expression: sub } => {
                // DW_OP_entry_value / GNU: nested sub-expression. Its bytes are the tail of this
                // operation; compute its base relative to the original buffer.
                let sub_base = base + (end - sub.slice().len());
                walk_expression(gimli::Expression(sub), sub_base, encoding, on_ref, on_sec_ref)?;
            }
            gimli::Operation::VariableValue { offset } => {
                // DW_OP_GNU_variable_value: section-absolute .debug_info offset.
                on_sec_ref(offset.0);
            }
            _ => {}
        }
        start = end;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefFormKind {
    CuRelative,
    SectionAbsolute,
}

/// Is this form one of the DWARF `reference` class forms that we treat as a edge
/// when marking?
///
/// Returns the kind of edge (CU-relative vs section-absolute), or `None` for
/// non-reference forms and for forms we deliberately skip (`ref_sig8`,
/// `ref_sup4/8`).
fn ref_form_kind(form: gimli::DwForm) -> Option<RefFormKind> {
    use gimli::constants::*;
    match form {
        DW_FORM_ref1 | DW_FORM_ref2 | DW_FORM_ref4 | DW_FORM_ref8 | DW_FORM_ref_udata => {
            Some(RefFormKind::CuRelative)
        }
        DW_FORM_ref_addr => Some(RefFormKind::SectionAbsolute),
        // Skipped: ref_sig8 (type unit), ref_sup4/8 (supplementary file).
        _ => None,
    }
}

/// Check whether a DWARF4 range list (`.debug_ranges`) contains any non-tombstoned entry.
///
/// DWARF4 `.debug_ranges` uses raw address pairs (parsed as `BaseAddress` or
/// `AddressOrOffsetPair` by gimli). The `sec_offset` from `DW_AT_ranges` indexes
/// directly into the `.debug_ranges` data held by `range_lists`.
///
/// Returns `Ok(true)` if at least one entry resolves to a non-tombstoned address,
/// `Ok(false)` if all entries are tombstoned or the list was empty.
/// Conservatively returns `Ok(true)` if resolution fails.
fn ranges_has_live_entry(
    range_lists: &gimli::RangeLists<Relocate<gimli::EndianSlice<'_, RunTimeEndian>>>,
    offset: gimli::RangeListsOffset<usize>,
    encoding: gimli::Encoding,
    dwo_id: DwoId,
) -> Result<bool> {
    let address_size = encoding.address_size;

    let Ok(mut raw_iter) = range_lists.raw_ranges(offset, encoding) else {
        debug!(?dwo_id, offset = %format_args!("{:#x}", offset.0), "Can't parse ranges at offset, conservatively assuming live.");
        return Ok(true);
    };

    let mut base_tombstoned = false;

    while let Some(entry) = raw_iter.next()? {
        match entry {
            gimli::RawRngListEntry::BaseAddress { addr } => {
                base_tombstoned = is_tombstone(addr, address_size);
            }
            gimli::RawRngListEntry::AddressOrOffsetPair { begin, .. } => {
                if base_tombstoned {
                    continue;
                }
                if !is_tombstone(begin, address_size) {
                    return Ok(true);
                }
            }
            _ => {
                debug!(
                    ?dwo_id,
                    "Unexpected entry type in .debug_ranges, conservatively assuming live."
                );
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Check whether a DWARF5 range list (`.debug_rnglists`) contains any non-tombstoned entry.
///
/// Returns `Ok(true)` if at least one entry resolves to a non-tombstoned address,
/// `Ok(false)` if all entries are tombstoned or the list was empty.
/// Conservatively returns `Ok(true)` if resolution fails.
fn rnglist_has_live_entry<IsAddrLive>(
    range_lists: &gimli::RangeLists<Relocate<gimli::EndianSlice<'_, RunTimeEndian>>>,
    base: gimli::DebugRngListsBase<usize>,
    index: gimli::DebugRngListsIndex<usize>,
    encoding: gimli::Encoding,
    is_addr_live: &IsAddrLive,
    dwo_id: DwoId,
) -> Result<bool>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    // Resolve the rnglistx index to an absolute section offset.
    let Ok(offset) = range_lists.get_offset(encoding, base, index) else {
        debug!(?dwo_id, base = %format_args!("{:#x}", base.0), index = %format_args!("{:#x}", index.0), "Can't get rnglist offset, conservatively assuming live.");
        return Ok(true);
    };

    let Ok(mut raw_iter) = range_lists.raw_ranges(offset, encoding) else {
        debug!(?dwo_id, offset = %format_args!("{:#x}", offset.0), "Can't parse rnglist at offset, conservatively assuming live.");
        return Ok(true);
    };

    let mut base_tombstoned = false;

    while let Some(entry) = raw_iter.next()? {
        match entry {
            gimli::RawRngListEntry::BaseAddressx { addr } => {
                base_tombstoned = !is_addr_live(addr)?;
            }
            gimli::RawRngListEntry::BaseAddress { addr } => {
                base_tombstoned = is_tombstone(addr, encoding.address_size);
            }
            gimli::RawRngListEntry::OffsetPair { .. }
            | gimli::RawRngListEntry::AddressOrOffsetPair { .. } => {
                if !base_tombstoned {
                    return Ok(true);
                }
            }
            gimli::RawRngListEntry::StartxEndx { begin, .. }
            | gimli::RawRngListEntry::StartxLength { begin, .. } => {
                if is_addr_live(begin)? {
                    return Ok(true);
                }
            }
            gimli::RawRngListEntry::StartEnd { begin, .. }
            | gimli::RawRngListEntry::StartLength { begin, .. } => {
                if !is_tombstone(begin, encoding.address_size) {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

/// Determine whether a `DW_TAG_subprogram`/`DW_TAG_variable` (or any root) is a live root.
///
/// `attrs` are the raw `(name, form, value)` records of the DIE. Returns `Ok(true)` if the DIE
/// should be treated as an unconditionally live root. Conservatively returns `true` when liveness
/// cannot be determined.
fn is_root<IsAddrLive>(
    tag: gimli::DwTag,
    attrs: &[(
        gimli::DwAt,
        gimli::DwForm,
        gimli::AttributeValue<gimli::EndianSlice<'_, RunTimeEndian>>,
    )],
    range_lists: &gimli::RangeLists<Relocate<gimli::EndianSlice<'_, RunTimeEndian>>>,
    rnglists_base: gimli::DebugRngListsBase<usize>,
    is_addr_live: &IsAddrLive,
    dwo_id: DwoId,
    encoding: gimli::Encoding,
) -> Result<bool>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    match tag {
        gimli::DW_TAG_subprogram => {
            // DW_AT_low_pc via addrx*: live if the resolved address is not a tombstone.
            for (name, _, value) in attrs {
                if *name == gimli::DW_AT_low_pc {
                    if let gimli::AttributeValue::DebugAddrIndex(idx) = value {
                        if is_addr_live(*idx)? {
                            return Ok(true);
                        }
                    } else if let gimli::AttributeValue::Addr(addr) = value {
                        // Direct address (unusual in .dwo, but be safe).
                        if !is_tombstone(*addr, encoding.address_size) {
                            return Ok(true);
                        }
                    } else {
                        // Unknown low_pc form: conservatively live.
                        return Ok(true);
                    }
                }
            }
            // DW_AT_ranges: live if any range list entry has a non-tombstoned address.
            for (name, _, value) in attrs {
                if *name == gimli::DW_AT_ranges {
                    if let gimli::AttributeValue::DebugRngListsIndex(idx) = value {
                        return rnglist_has_live_entry(
                            range_lists,
                            rnglists_base,
                            *idx,
                            encoding,
                            is_addr_live,
                            dwo_id,
                        );
                    } else if let gimli::AttributeValue::SecOffset(offset) = value {
                        return ranges_has_live_entry(
                            range_lists,
                            gimli::RangeListsOffset(*offset),
                            encoding,
                            dwo_id,
                        );
                    } else {
                        // Unknown ranges form: conservatively live.
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        gimli::DW_TAG_variable => {
            for (name, _, value) in attrs {
                if *name == gimli::DW_AT_location {
                    if let gimli::AttributeValue::Exprloc(expr) = value {
                        if location_expr_live(*expr, is_addr_live, encoding)? {
                            return Ok(true);
                        }
                    }
                    // Location list forms (loclistx, sec_offset, etc.) or other
                    // non-exprloc forms describe local variables whose location
                    // varies across PC ranges. They have no independent static
                    // address and cannot be roots.
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Examine a variable's location expression for `DW_OP_addrx` / `DW_OP_GNU_addr_index`.
fn location_expr_live<IsAddrLive>(
    expression: gimli::Expression<gimli::EndianSlice<'_, RunTimeEndian>>,
    is_addr_live: &IsAddrLive,
    encoding: gimli::Encoding,
) -> Result<bool>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    let mut iter = expression.operations(encoding);
    let mut saw_addrx = false;
    let mut any_live = false;
    while let Some(op) = iter.next()? {
        if let gimli::Operation::AddressIndex { index } = op {
            saw_addrx = true;
            if is_addr_live(index)? {
                any_live = true;
            }
        }
    }
    if saw_addrx {
        Ok(any_live)
    } else {
        Ok(false)
    }
}

/// Scan a single fully-live DIE's attributes for tracing edges.
fn scan_live_die_attrs(
    attrs: &[(
        gimli::DwAt,
        gimli::DwForm,
        gimli::AttributeValue<gimli::EndianSlice<'_, RunTimeEndian>>,
    )],
    loc_lists: &gimli::LocationLists<gimli::EndianSlice<'_, RunTimeEndian>>,
    loclists_base: gimli::DebugLocListsBase<usize>,
    encoding: gimli::Encoding,
) -> Result<Vec<gimli::UnitOffset>> {
    let mut out = Vec::new();
    for (name, form, value) in attrs {
        // DW_AT_sibling links don't keep DIEs alive.
        if *name == gimli::DW_AT_sibling {
            continue;
        }

        // Reference-form attributes.
        // Handling DW_FORM_indirect is tricky. gimli resolves it
        // transparently, so the value contains the resolved attribute
        // (e.g. UnitRef for an inner ref4), but the form from the
        // abbreviation table is still DW_FORM_indirect. Check both
        // the declared form and the resolved value type.
        match ref_form_kind(*form) {
            Some(RefFormKind::CuRelative) => {
                if let gimli::AttributeValue::UnitRef(unit_off) = value {
                    out.push(*unit_off);
                }
            }
            None => {
                // DW_FORM_indirect wrapping a reference form: gimli resolves the
                // inner form and produces a UnitRef value even though the outer form
                // is DW_FORM_indirect.
                if *form == gimli::DW_FORM_indirect {
                    if let gimli::AttributeValue::UnitRef(unit_off) = value {
                        out.push(*unit_off);
                    }
                }
            }
            Some(RefFormKind::SectionAbsolute) => {
                // DW_FORM_ref_addr does not occur in .dwo files produced by any
                // toolchain known to me. LLVM merges CUs to avoid cross-CU
                // references in split DWARF output, and GCC does not support
                // split DWARF with LTO at all. The only way I could find to produce
                // it is `llc -split-dwarf-cross-cu-references`, an experimental
                // flag not exposed through any compiler driver. Error out so that
                // if a future toolchain does emit ref_addr we notice.
                return Err(Error::UnexpectedSectionAbsoluteReference);
            }
        }

        // Expressions embedded in exprloc attributes.
        if let gimli::AttributeValue::Exprloc(expr) = value {
            let mut on_ref = |r: ExprRef| out.push(r.old);
            // Section-absolute expression refs (DW_OP_call_ref, DW_OP_implicit_pointer,
            // DW_OP_GNU_variable_value) should not occur in .dwo files; see comment on
            // RefFormKind::SectionAbsolute above.
            let mut saw_section_absolute_reference = false;
            let mut on_sec = |_: usize| {
                saw_section_absolute_reference = true;
            };
            walk_expression(*expr, 0, encoding, &mut on_ref, &mut on_sec)?;
            if saw_section_absolute_reference {
                return Err(Error::UnexpectedSectionAbsoluteReference);
            }
        }

        // Location lists referenced by DW_AT_location via loclistx / sec_offset.
        if *name == gimli::DW_AT_location {
            let loclist_offset = match value {
                gimli::AttributeValue::SecOffset(off) => Some(*off),
                gimli::AttributeValue::LocationListsRef(off) => Some(off.0),
                gimli::AttributeValue::DebugLocListsIndex(idx) => {
                    Some(loc_lists.get_offset(encoding, loclists_base, *idx)?.0)
                }
                _ => None,
            };
            if let Some(off) = loclist_offset {
                scan_loclist_for_refs(loc_lists, off, encoding, &mut out)?;
            }
        }
    }
    Ok(out)
}

/// Parse a DWARF5 `.debug_loclists.dwo` location list starting at byte `start`,
/// scanning each location expression for CU-relative DIE references.
fn scan_loclist_for_refs(
    loc_lists: &gimli::LocationLists<gimli::EndianSlice<'_, RunTimeEndian>>,
    start: usize,
    encoding: gimli::Encoding,
    out: &mut Vec<gimli::UnitOffset>,
) -> Result<()> {
    let mut raw_iter = loc_lists.raw_locations_dwo(gimli::LocationListsOffset(start), encoding)?;
    while let Some(raw_entry) = raw_iter.next()? {
        // Extract expression from variants that carry one.
        let expr: Option<gimli::Expression<gimli::EndianSlice<'_, RunTimeEndian>>> =
            match &raw_entry {
                gimli::RawLocListEntry::StartxEndx { data, .. }
                | gimli::RawLocListEntry::StartxLength { data, .. }
                | gimli::RawLocListEntry::OffsetPair { data, .. }
                | gimli::RawLocListEntry::DefaultLocation { data }
                | gimli::RawLocListEntry::StartEnd { data, .. }
                | gimli::RawLocListEntry::StartLength { data, .. }
                | gimli::RawLocListEntry::AddressOrOffsetPair { data, .. } => Some(*data),
                // BaseAddressx, BaseAddress - no expression.
                _ => None,
            };
        if let Some(expr) = expr {
            let mut on_ref = |r: ExprRef| out.push(r.old);
            // As discussed above, section-absolute expression refs should not
            // occur in .dwo files.
            let mut saw_section_absolute_reference = false;
            let mut on_sec = |_: usize| {
                saw_section_absolute_reference = true;
            };
            walk_expression(expr, 0, encoding, &mut on_ref, &mut on_sec)?;
            if saw_section_absolute_reference {
                return Err(Error::UnexpectedSectionAbsoluteReference);
            }
        }
    }
    Ok(())
}

/// Garbage-collect dead DIEs from a `.debug_info.dwo` compilation unit.
///
/// See the module level comment for an explanation of the approach.
pub(crate) fn gc_debug_info<IsAddrLive>(
    debug_info: gimli::DebugInfo<gimli::EndianSlice<'_, RunTimeEndian>>,
    debug_abbrev: gimli::DebugAbbrev<gimli::EndianSlice<'_, RunTimeEndian>>,
    loc_lists: gimli::LocationLists<gimli::EndianSlice<'_, RunTimeEndian>>,
    range_lists: gimli::RangeLists<Relocate<gimli::EndianSlice<'_, RunTimeEndian>>>,
    is_addr_live: IsAddrLive,
    dwo_id: DwoId,
    has_type_units: bool,
) -> Result<GcResult>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    debug!(?dwo_id, has_type_units, "gc_debug_info: starting GC pass");

    // Step 1: Walk the DIEs, build the graph, and identify roots.
    let Some(header) = debug_info.units().next().map_err(Error::ParseUnitHeader)? else {
        return Ok(GcResult {
            rewritten: None,
            offset_remap: None,
            referenced_rnglists: None,
            referenced_loclists: None,
            referenced_str_offsets: None,
        });
    };
    let encoding = header.encoding();
    let abbreviations =
        header.abbreviations(&debug_abbrev).map_err(Error::ParseUnitAbbreviations)?;

    // Walk every DIE, recording it and (for fully-live DIEs later) its edges.
    // We use `entries_raw` for byte-precise offsets.
    let mut entries = header.entries_raw(&abbreviations, None).map_err(Error::ParseUnit)?;

    let mut dies: Vec<DieRecord> = Vec::new();
    // Map from CU-relative DIE offset -> index in `dies`.
    let mut offset_to_index: HashMap<gimli::UnitOffset, usize> = HashMap::new();
    // Roots discovered during the walk.
    let mut worklist: Vec<usize> = Vec::new();
    // Per-DIE rnglistx indices (from DW_FORM_rnglistx attributes).
    let mut die_rnglistx: Vec<Vec<u64>> = Vec::new();
    // Per-DIE loclistx indices (from DW_FORM_loclistx attributes).
    let mut die_loclistx: Vec<Vec<u64>> = Vec::new();
    // Per-DIE strx indices (from DW_FORM_strx* attributes).
    let mut die_strx: Vec<Vec<u64>> = Vec::new();

    // Stack of currently-open parent DIE indices (those with `has_children`).
    // Each null entry in the byte stream terminates exactly one such children
    // list, so closes one parent.
    let mut parent_stack: Vec<usize> = Vec::new();

    let mut can_prune_rnglists = !has_type_units;
    let mut can_prune_loclists = !has_type_units;
    let can_prune_str_offsets = !has_type_units;

    // The rnglists base used to resolve DW_FORM_rnglistx indices. Initialized
    // to the default (header-size-only), but overridden by DW_AT_rnglists_base
    // on the CU DIE.
    let mut rnglists_base = gimli::DebugRngListsBase::default_for_encoding_and_file(
        encoding,
        gimli::DwarfFileType::Dwo,
    );
    // The loclists base used to resolve DW_FORM_loclistx indices. Initialized
    // to the default (header-size-only), but overridden by DW_AT_loclists_base
    // on the CU DIE.
    let mut loclists_base = gimli::DebugLocListsBase::default_for_encoding_and_file(
        encoding,
        gimli::DwarfFileType::Dwo,
    );

    while !entries.is_empty() {
        let offset = entries.next_offset();
        let Some(abbrev) = entries.read_abbreviation().map_err(Error::ParseUnit)? else {
            parent_stack.pop();
            continue;
        };

        let tag = abbrev.tag();
        let has_children = abbrev.has_children();

        let mut attrs: Vec<(gimli::DwAt, gimli::DwForm, gimli::AttributeValue<_>)> =
            Vec::with_capacity(abbrev.attributes().len());
        for spec in abbrev.attributes() {
            let attr = entries.read_attribute(*spec).map_err(Error::ParseUnit)?;
            attrs.push((spec.name(), spec.form(), attr.raw_value()));
        }

        // Extract DW_AT_rnglists_base/DW_AT_loclists_base from the CU DIE
        // so we can correctly resolve rnglistx/loclistx indices in child DIEs.
        // The raw_value() for DW_FORM_sec_offset is AttributeValue::SecOffset;
        // the normalization to DebugRngListsBase/DebugLocListsBase happens
        // only in the value() accessor.
        if tag == gimli::DW_TAG_compile_unit {
            for (name, _, value) in &attrs {
                if *name == gimli::DW_AT_rnglists_base {
                    if let gimli::AttributeValue::SecOffset(offset) = value {
                        rnglists_base = gimli::DebugRngListsBase(*offset);
                    }
                }
                if *name == gimli::DW_AT_loclists_base {
                    if let gimli::AttributeValue::SecOffset(offset) = value {
                        loclists_base = gimli::DebugLocListsBase(*offset);
                    }
                }
            }
        }

        let index = dies.len();
        offset_to_index.insert(offset, index);

        // Identify roots.
        let mut liveness = Liveness::Dead;
        if is_root(tag, &attrs, &range_lists, rnglists_base, &is_addr_live, dwo_id, encoding)? {
            liveness = Liveness::Live;
            worklist.push(index);
        }

        // Capture section references for post-GC pruning.
        let mut rnglistx_vals: Vec<u64> = Vec::new();
        let mut loclistx_vals: Vec<u64> = Vec::new();
        let mut strx_vals: Vec<u64> = Vec::new();
        for (name, form, value) in &attrs {
            if *form == gimli::DW_FORM_sec_offset {
                if *name == gimli::DW_AT_ranges {
                    warn!(
                        ?dwo_id,
                        "DW_AT_ranges uses DW_FORM_sec_offset; disabling rnglists pruning"
                    );
                    can_prune_rnglists = false;
                } else if *name == gimli::DW_AT_location {
                    warn!(
                        ?dwo_id,
                        "DW_AT_location uses DW_FORM_sec_offset; disabling loclists pruning"
                    );
                    can_prune_loclists = false;
                }
            }
            if let gimli::AttributeValue::DebugRngListsIndex(idx) = value {
                rnglistx_vals.push(idx.0 as u64);
            }
            if let gimli::AttributeValue::DebugLocListsIndex(idx) = value {
                loclistx_vals.push(idx.0 as u64);
            }
            if let gimli::AttributeValue::DebugStrOffsetsIndex(idx) = value {
                strx_vals.push(idx.0 as u64);
            }
        }

        // Collect outgoing edges (used only when this DIE is fully live).
        let edges = scan_live_die_attrs(&attrs, &loc_lists, loclists_base, encoding)?;

        let parent = parent_stack.last().copied();
        dies.push(DieRecord { parent, children: vec![], edges, liveness });
        if let Some(parent) = parent {
            dies[parent].children.push(index);
        }
        die_rnglistx.push(rnglistx_vals);
        die_loclistx.push(loclistx_vals);
        die_strx.push(strx_vals);

        if has_children {
            parent_stack.push(index);
        }
    }

    if dies.is_empty() {
        return Ok(GcResult {
            rewritten: None,
            offset_remap: None,
            referenced_rnglists: None,
            referenced_loclists: None,
            referenced_str_offsets: None,
        });
    }

    // The CU root must always survive even if every child DIE is dead. The
    // skeleton CU in the linked executable references this CU by DwoId;
    // dropping it from the .dwp would leave a dangling reference. That can't be
    // fixed without modifying the executable, which we don't do.
    //
    // But note that we don't seed it as a *live* root because that would
    // propagate downward to everything in the CU, entirely defeating the
    // purpose of the GC.
    dies[0].liveness = Liveness::Retained;

    // Step 2: Mark-and-sweep to fixed point:
    //   1. Drain worklist (Live propagation down + edge tracing).
    //   2. Upward retention for ancestors of Live DIEs.
    //   3. Trace reference edges from Retained DIEs → newly Live targets.
    // Repeat until stable. Step 3 is necessary because a Retained DIE (kept only for tree
    // structure) may carry a reference edge (e.g. DW_FORM_ref4) whose target is otherwise Dead;
    // that target's bytes must survive so the retained reference doesn't dangle after rewrite.
    loop {
        while let Some(i) = worklist.pop() {
            // Downward: all descendants become fully live.

            // XXXkhuey arguably we should stop our descent at "things that
            // could have become roots but didn't", so e.g. a live subprogram
            // would keep alive a DW_TAG_variable for a local variable inside
            // itself but not a DW_TAG_subprogram for a nested subprogram that
            // became dead code. This brings along the entire descendant tree.

            // NB: Safe to mem::take because this is the only code that examines
            // `children` and we will never add a DIE to the worklist twice.
            let children = mem::take(&mut dies[i].children);
            for c in children.into_iter() {
                if dies[c].liveness != Liveness::Live {
                    dies[c].liveness = Liveness::Live;
                    worklist.push(c);
                }
            }
            // Trace outgoing edges.
            // NB: Safe to mem::take because the code below that examines `edges`
            // only ever operates on Retained DIEs, and we will never add a DIE
            // to the worklist twice, and we will never "demote" a Live DIE to
            // Retained/Dead.
            let edges = mem::take(&mut dies[i].edges);
            for target in edges.into_iter() {
                if let Some(&ti) = offset_to_index.get(&target) {
                    if dies[ti].liveness != Liveness::Live {
                        dies[ti].liveness = Liveness::Live;
                        worklist.push(ti);
                    }
                }
            }
        }

        // Upward: mark ancestors of every live DIE as (at least) structurally retained.
        for i in 0..dies.len() {
            if dies[i].liveness != Liveness::Live {
                continue;
            }

            let mut p = dies[i].parent;
            while let Some(pi) = p {
                if dies[pi].liveness == Liveness::Dead {
                    dies[pi].liveness = Liveness::Retained;
                    p = dies[pi].parent;
                } else {
                    // Already live or retained: ancestors above are handled too.
                    break;
                }
            }
        }

        // Trace edges from Retained DIEs; any non-Live target becomes Live and
        // re-enters the loop.
        for i in 0..dies.len() {
            if dies[i].liveness != Liveness::Retained {
                continue;
            }

            // Safe to mem::take because once a Retained DIE's edge targets are
            // promoted, rescanning the DIE would find all edge targets
            // already Live and produce no new work.
            let edges = mem::take(&mut dies[i].edges);
            for target in edges.into_iter() {
                if let Some(&ti) = offset_to_index.get(&target) {
                    if dies[ti].liveness != Liveness::Live {
                        dies[ti].liveness = Liveness::Live;
                        worklist.push(ti);
                    }
                }
            }
        }

        if worklist.is_empty() {
            break;
        }
    }

    // Step 3: Collect section references from surviving DIEs for post-GC pruning.
    let mut referenced_rnglists = BTreeSet::new();
    let mut referenced_loclists = BTreeSet::new();
    let mut referenced_str_offsets = BTreeSet::new();
    let total_dies = dies.len();
    let mut dead_dies = 0;
    assert_eq!(total_dies, die_rnglistx.len());
    assert_eq!(total_dies, die_loclistx.len());
    assert_eq!(total_dies, die_strx.len());
    for (die, rnglistx, loclistx, strx) in
        izip!(&dies, die_rnglistx.into_iter(), die_loclistx.into_iter(), die_strx.into_iter())
    {
        if die.liveness == Liveness::Dead {
            dead_dies += 1;
            continue;
        }
        referenced_rnglists.extend(rnglistx);
        referenced_loclists.extend(loclistx);
        referenced_str_offsets.extend(strx);
    }

    let referenced_rnglists = if can_prune_rnglists { Some(referenced_rnglists) } else { None };
    let referenced_loclists = if can_prune_loclists { Some(referenced_loclists) } else { None };
    let referenced_str_offsets =
        if can_prune_str_offsets { Some(referenced_str_offsets) } else { None };
    // If every DIE survived, nothing to do.
    if dead_dies == 0 {
        return Ok(GcResult {
            rewritten: None,
            offset_remap: None,
            referenced_rnglists,
            referenced_loclists,
            referenced_str_offsets,
        });
    }

    debug!(?dwo_id, total_dies, dead_dies, "gc_debug_info: pruning dead DIEs");

    // Build index remapping for compacting offset tables. Each referenced index
    // maps to its position in the sorted set (its new compact index).
    let rnglist_remap: Option<HashMap<u64, u64>> = referenced_rnglists
        .as_ref()
        .map(|set| set.iter().enumerate().map(|(new, &old)| (old, new as u64)).collect());
    let loclist_remap: Option<HashMap<u64, u64>> = referenced_loclists
        .as_ref()
        .map(|set| set.iter().enumerate().map(|(new, &old)| (old, new as u64)).collect());
    let strx_remap: Option<HashMap<u64, u64>> = referenced_str_offsets
        .as_ref()
        .map(|set| set.iter().enumerate().map(|(new, &old)| (old, new as u64)).collect());

    // Step 4: rewrite at byte level
    let (rewritten, new_offset) = rewrite_unit(
        debug_info,
        &header,
        &abbreviations,
        &dies,
        &offset_to_index,
        rnglist_remap.as_ref(),
        loclist_remap.as_ref(),
        strx_remap.as_ref(),
    )?;
    Ok(GcResult {
        rewritten: Some(rewritten),
        offset_remap: Some(new_offset),
        referenced_rnglists,
        referenced_loclists,
        referenced_str_offsets,
    })
}

/// Rewrite the unit's bytes, dropping dead DIEs and patching surviving CU-relative references.
///
/// Each surviving DIE is emitted at exactly its original byte size: attribute bytes are copied
/// verbatim and only the values of CU-relative reference attributes are updated in place.
///
/// The key insight that makes this ok is that offsets only ever shrink, they cannot expand.
/// Updating values for fixed-width reference forms is trivial. For variable-width reference
/// forms we take advantage of the fact that ULEB128 makes it straightforward to "pad" a
/// lower value to the size of a higher value.
///
/// We're not producing the absolutely minimal byte sizes here but what we are leaving
/// on the table is immaterial compared to our gains.
fn rewrite_unit(
    debug_info: gimli::DebugInfo<gimli::EndianSlice<'_, RunTimeEndian>>,
    header: &gimli::UnitHeader<gimli::EndianSlice<'_, RunTimeEndian>>,
    abbreviations: &gimli::Abbreviations,
    dies: &[DieRecord],
    offset_to_index: &HashMap<gimli::UnitOffset, usize>,
    rnglist_remap: Option<&HashMap<u64, u64>>,
    loclist_remap: Option<&HashMap<u64, u64>>,
    strx_remap: Option<&HashMap<u64, u64>>,
) -> Result<(EndianVec<RunTimeEndian>, BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>)> {
    let endian = debug_info.reader().endian();
    let encoding = header.encoding();
    let header_size = header.size_of_header();

    // Step 1: compute new offsets for surviving DIEs.
    // CU-relative references (DW_FORM_ref*) can point forward to DIEs not yet emitted, so we
    // can't patch references in a single pass. Instead, walk the DIE stream to compute
    // every surviving DIE's new offset, then later emit the final bytes with all references
    // patched. This works because reference patches never change byte width (offsets only shrink,
    // and ULEB128 patches are padded to the original width), so each surviving DIE occupies
    // exactly its original number of bytes in both passes.
    let mut new_offset = BTreeMap::new();
    {
        let mut scratch = EndianVec::new(endian);
        emit_dies(
            header,
            abbreviations,
            dies,
            offset_to_index,
            None,
            rnglist_remap,
            loclist_remap,
            strx_remap,
            &mut new_offset,
            &mut scratch,
        )?;
    }

    // Step 2: emit with patches using the final `new_offset` map.
    let mut body = EndianVec::new(endian);
    {
        let mut discard = BTreeMap::new();
        emit_dies(
            header,
            abbreviations,
            dies,
            offset_to_index,
            Some(&new_offset),
            rnglist_remap,
            loclist_remap,
            strx_remap,
            &mut discard,
            &mut body,
        )?;
    }

    // Assemble the output: header + body.
    let mut out = EndianVec::new(endian);
    out.write(&debug_info.reader().slice()[..header_size])?;
    out.write(body.slice())?;

    // Patch unit_length in the header. unit_length excludes the initial length field itself.
    let is_dwarf64 = encoding.format == gimli::Format::Dwarf64;
    let new_unit_length = (out.slice().len() - if is_dwarf64 { 12 } else { 4 }) as u64;
    if is_dwarf64 {
        out.write_u64_at(4, new_unit_length)?;
    } else {
        out.write_u32_at(
            0,
            new_unit_length.try_into().expect("unit length w/out header larger than u32"),
        )?;
    }

    Ok((out, new_offset))
}

/// Walk the raw DIE byte stream, emitting surviving DIEs to `out` and skipping dead ones.
///
/// `dies` is the pre-order list from the analysis pass; this walk visits DIEs
/// in the same order, so `die_idx` advances in lockstep. For each surviving DIE,
/// its new offset (relative to the unit start) is recorded in `new_offset`
/// (keyed by old offset). When `patch` is `Some`, CU-relative references are
/// rewritten to their new offsets; when `None` (offset-computation pass), bytes
/// are emitted unpatched (their length is what matters).
fn emit_dies(
    header: &gimli::UnitHeader<gimli::EndianSlice<'_, RunTimeEndian>>,
    abbreviations: &gimli::Abbreviations,
    dies: &[DieRecord],
    offset_to_index: &HashMap<gimli::UnitOffset, usize>,
    patch: Option<&BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>>,
    rnglist_remap: Option<&HashMap<u64, u64>>,
    loclist_remap: Option<&HashMap<u64, u64>>,
    strx_remap: Option<&HashMap<u64, u64>>,
    new_offset: &mut BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>,
    out: &mut EndianVec<RunTimeEndian>,
) -> Result<()> {
    let mut entries_raw = header.entries_raw(abbreviations, None).map_err(Error::ParseUnit)?;

    // Stack tracks whether each open parent with children is being emitted,
    // so we know whether to write null terminators when their children list ends.
    let mut emit_stack: Vec<bool> = Vec::new();

    while !entries_raw.is_empty() {
        let die_start = entries_raw.next_offset();
        let new_off = gimli::UnitOffset(header.root_offset().0 + out.slice().len());
        let Some(abbrev) =
            entries_raw.read_abbreviation().map_err(Error::ParseUnitAbbreviations)?
        else {
            if emit_stack.pop() == Some(true) {
                new_offset.insert(die_start, (new_off, emit_stack.len() + 1));
                out.write_u8(0)?;
            }
            continue;
        };

        let die_index = *offset_to_index.get(&die_start).ok_or(Error::MalformedDebugInfo)?;
        let emit = dies[die_index].liveness != Liveness::Dead;

        if emit {
            new_offset.insert(die_start, (new_off, emit_stack.len()));

            let after_code = entries_raw.next_offset();
            out.write(&header.range(die_start..after_code)?)?;

            for spec in abbrev.attributes() {
                let attr_start = entries_raw.next_offset();
                entries_raw.read_attribute(*spec)?;
                let attr_end = entries_raw.next_offset();
                if attr_end > attr_start {
                    emit_attribute(
                        header,
                        header.range(attr_start..attr_end)?,
                        spec,
                        emit_stack.len(),
                        patch,
                        rnglist_remap,
                        loclist_remap,
                        strx_remap,
                        out,
                    )?;
                }
            }
        } else {
            entries_raw.skip_attributes(abbrev.attributes())?;
        }

        if abbrev.has_children() {
            emit_stack.push(emit);
        }
    }

    Ok(())
}

/// Emit a single attribute value (the bytes in `data`) to `out`, patching CU-relative references
/// when `patch` is `Some`.
fn emit_attribute(
    header: &gimli::UnitHeader<gimli::EndianSlice<'_, RunTimeEndian>>,
    mut data: gimli::EndianSlice<'_, RunTimeEndian>,
    spec: &gimli::AttributeSpecification,
    depth: usize,
    patch: Option<&BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>>,
    rnglist_remap: Option<&HashMap<u64, u64>>,
    loclist_remap: Option<&HashMap<u64, u64>>,
    strx_remap: Option<&HashMap<u64, u64>>,
    out: &mut EndianVec<RunTimeEndian>,
) -> Result<()> {
    use gimli::constants::*;

    let name = spec.name();
    let form = spec.form();

    // Resolve DW_FORM_indirect to its inline form first, copying the form ULEB128 bytes.
    if form == DW_FORM_indirect {
        let orig = data;
        let inner = data.read_uleb128()?;
        // Copy the form selector bytes verbatim.
        out.write(&orig.range_to(..data.offset_from(orig)))?;
        let inner_form = gimli::DwForm(inner as u16);
        let inner_spec = gimli::AttributeSpecification::new(name, inner_form, None);
        return emit_attribute(
            header,
            data,
            &inner_spec,
            depth,
            patch,
            rnglist_remap,
            loclist_remap,
            strx_remap,
            out,
        );
    }

    // When not patching (offset-computation pass), just copy verbatim.
    let Some(patch) = patch else {
        out.write(&data)?;
        return Ok(());
    };

    // CU-relative reference forms: patch to new offset (same byte width).
    if matches!(form, DW_FORM_ref1 | DW_FORM_ref2 | DW_FORM_ref4 | DW_FORM_ref8 | DW_FORM_ref_udata)
    {
        let old = read_ref_value(data, form)?;
        let new = match patch.get(&old) {
            Some(n) => n.0,
            None => {
                // Target was dead. For DW_AT_sibling this can happen.
                // Otherwise this should be impossible.
                if name == DW_AT_sibling {
                    patch
                        .range(old..)
                        .skip_while(|&(_, v)| v.1 > depth)
                        .next()
                        .ok_or(Error::MalformedDebugInfo)?
                        .1
                         .0
                } else {
                    return Err(Error::MalformedDebugInfo);
                }
            }
        };
        write_ref_value(out, form, old, new)?;
        return Ok(());
    }

    // exprloc: copy length prefix, then patch embedded CU-relative references in the expression.
    if form == DW_FORM_exprloc {
        let orig = data;
        let expr_len = data.read_uleb128()? as usize;
        // Copy the length prefix verbatim.
        out.write(&orig.range_to(..data.offset_from(orig)))?;
        // Then patch the expression.
        emit_expression(data.range_to(..expr_len), patch, header.encoding(), out)?;
        return Ok(());
    }

    // rnglistx/loclistx/strx: remap to compacted offset table index.
    let remap = match form {
        DW_FORM_rnglistx => rnglist_remap,
        DW_FORM_loclistx => loclist_remap,
        DW_FORM_strx | DW_FORM_GNU_str_index => strx_remap,
        _ => None,
    };
    if let Some(remap) = remap {
        let old_width = data.len();
        let old_idx = data.read_uleb128()?;
        let &new_idx = remap.get(&old_idx).ok_or(Error::MalformedDebugInfo)?;
        write_uleb128_padded(out, gimli::UnitOffset(new_idx as usize), old_width)?;
        return Ok(());
    }

    // Fixed-width strx forms: remap to compacted str_offsets table index.
    let fixed_width: u8 = match form {
        DW_FORM_strx1 => 1,
        DW_FORM_strx2 => 2,
        DW_FORM_strx3 => 3,
        DW_FORM_strx4 => 4,
        _ => 0,
    };
    if fixed_width > 0 {
        if let Some(strx_remap) = strx_remap {
            let old_idx = data.read_uint(fixed_width as usize)?;
            let &new_idx = strx_remap.get(&old_idx).ok_or(Error::MalformedDebugInfo)?;
            out.write_udata(new_idx, fixed_width)?;
            return Ok(());
        }
    }

    // Everything else: copy verbatim.
    out.write(&data)?;
    Ok(())
}

/// Read a CU-relative reference value of the given reference form at `pos`.
fn read_ref_value(
    mut data: gimli::EndianSlice<'_, RunTimeEndian>,
    form: gimli::DwForm,
) -> Result<gimli::UnitOffset> {
    use gimli::constants::*;
    Ok(gimli::UnitOffset(match form {
        DW_FORM_ref1 => data.read_u8()? as usize,
        DW_FORM_ref2 => data.read_u16()? as usize,
        DW_FORM_ref4 => data.read_u32()? as usize,
        DW_FORM_ref8 => data.read_u64()? as usize,
        DW_FORM_ref_udata => data.read_uleb128()? as usize,
        _ => return Err(Error::UnsupportedForm(form.0)),
    }))
}

/// Write a CU-relative reference value of the given reference form to `out`, keeping the original
/// byte width. `old` is used to determine the original ULEB128 width for padding.
fn write_ref_value(
    out: &mut EndianVec<RunTimeEndian>,
    form: gimli::DwForm,
    old: gimli::UnitOffset,
    new: gimli::UnitOffset,
) -> Result<()> {
    use gimli::constants::*;
    match form {
        DW_FORM_ref1 => out.write_u8(new.0 as u8)?,
        DW_FORM_ref2 => out.write_u16(new.0 as u16)?,
        DW_FORM_ref4 => out.write_u32(new.0 as u32)?,
        DW_FORM_ref8 => out.write_u64(new.0 as u64)?,
        DW_FORM_ref_udata => {
            // Pad to the original number of bytes (offsets only shrink).
            let mut v = old.0 as u64;
            let mut width = 0;
            loop {
                width += 1;
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            write_uleb128_padded(out, new, width)?;
        }
        _ => return Err(Error::UnsupportedForm(form.0)),
    }
    Ok(())
}

/// Emit a DWARF expression (already length-prefixed by the caller), patching any embedded
/// CU-relative DIE references to their new offsets.
fn emit_expression(
    expr: gimli::EndianSlice<'_, RunTimeEndian>,
    patch: &BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>,
    encoding: gimli::Encoding,
    out: &mut EndianVec<RunTimeEndian>,
) -> Result<()> {
    let mut refs: Vec<ExprRef> = Vec::new();
    {
        let mut on_ref = |r: ExprRef| refs.push(r);
        let mut saw_section_absolute_reference = false;
        let mut on_sec = |_: usize| {
            saw_section_absolute_reference = true;
        };
        walk_expression(gimli::Expression(expr), 0, encoding, &mut on_ref, &mut on_sec)?;
        if saw_section_absolute_reference {
            return Err(Error::UnexpectedSectionAbsoluteReference);
        }
    }

    if refs.is_empty() {
        out.write(&expr)?;
        return Ok(());
    }

    // Patch references in increasing position order; for ULEB128 patches we keep the original
    // width so byte positions of later references are unchanged.
    refs.sort_by_key(|r| r.pos);
    let mut copied = 0usize;
    for r in &refs {
        // Copy bytes up to the reference operand.
        out.write(&expr[copied..r.pos])?;
        let new = patch.get(&r.old).ok_or(Error::MalformedDebugInfo)?.0;
        match r.enc {
            ExprRefEnc::U2 => {
                out.write_u16(new.0 as u16)?;
                copied = r.pos + 2;
            }
            ExprRefEnc::U4 => {
                out.write_u32(new.0 as u32)?;
                copied = r.pos + 4;
            }
            ExprRefEnc::Uleb => {
                let old_width = uleb128_len(expr.range_from(r.pos..))?;
                write_uleb128_padded(out, new, old_width)?;
                copied = r.pos + old_width;
            }
        }
    }
    out.write(&expr[copied..])?;
    Ok(())
}
