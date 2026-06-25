//! Stub module used when the `gc` feature is disabled.
//!
//! Exposes the same crate-internal surface as `gc.rs` so that `package.rs`
//! type-checks without any `#[cfg]` threading in the pipeline.  All functions
//! are no-ops that return `None`/`Ok(None)`.

#![allow(unused_variables)]

use std::collections::{BTreeMap, BTreeSet};

use gimli::{DebugAddrIndex, RunTimeEndian};

use crate::{error::Result, package::DwoId, relocate::Relocate};

/// Stub result of "garbage-collecting" a `.debug_info.dwo` compilation unit.
/// All fields are always `None` when the `gc` feature is disabled.
pub(crate) struct GcResult {
    pub rewritten: Option<gimli::write::EndianVec<RunTimeEndian>>,
    pub offset_remap: Option<BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>>,
    pub referenced_rnglists: Option<BTreeSet<u64>>,
    pub referenced_loclists: Option<BTreeSet<u64>>,
    pub referenced_str_offsets: Option<BTreeSet<u64>>,
}

pub(crate) fn is_tombstone(addr: u64, address_size: u8) -> bool {
    false
}

pub(crate) fn gc_debug_info<IsAddrLive>(
    _debug_info: gimli::DebugInfo<gimli::EndianSlice<'_, RunTimeEndian>>,
    _debug_abbrev: gimli::DebugAbbrev<gimli::EndianSlice<'_, RunTimeEndian>>,
    _loc_lists: gimli::LocationLists<gimli::EndianSlice<'_, RunTimeEndian>>,
    _range_lists: gimli::RangeLists<Relocate<gimli::EndianSlice<'_, RunTimeEndian>>>,
    _ranges_base: gimli::DebugRngListsBase<usize>,
    _is_addr_live: IsAddrLive,
    _dwo_id: DwoId,
    _has_type_units: bool,
) -> Result<GcResult>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    Ok(GcResult {
        rewritten: None,
        offset_remap: None,
        referenced_rnglists: None,
        referenced_loclists: None,
        referenced_str_offsets: None,
    })
}

pub(crate) fn rewrite_rnglists<IsAddrLive>(
    _data: gimli::EndianSlice<'_, RunTimeEndian>,
    _referenced_indices: &BTreeSet<u64>,
    _is_addr_live: &IsAddrLive,
    _dwo_id: DwoId,
) -> Result<Option<Vec<u8>>>
where
    IsAddrLive: Fn(DebugAddrIndex<usize>) -> Result<bool>,
{
    Ok(None)
}

pub(crate) fn patch_debug_loc(
    _data: gimli::EndianSlice<'_, RunTimeEndian>,
    _encoding: gimli::Encoding,
    _offset_remap: &BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>,
) -> Result<Option<Vec<u8>>> {
    Ok(None)
}

pub(crate) fn rewrite_loclists(
    _data: gimli::EndianSlice<'_, RunTimeEndian>,
    _referenced_indices: Option<&BTreeSet<u64>>,
    _offset_remap: Option<&BTreeMap<gimli::UnitOffset, (gimli::UnitOffset, usize)>>,
) -> Result<Option<Vec<u8>>> {
    Ok(None)
}
