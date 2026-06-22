use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt,
};

use gimli::{Encoding, Reader, RunTimeEndian, Section, UnitHeader, UnitIndex, UnitType};
use object::{
    write::{Object as WritableObject, SectionId},
    BinaryFormat, Object, ObjectSection, SectionKind,
};
use tracing::debug;

use crate::{
    error::{Error, Result},
    ext::{CompressedDataRangeExt, EndianityExt, IndexSectionExt, PackageFormatExt},
    gc::is_tombstone,
    index::{write_index, Bucketable, Contribution, ContributionOffset, IndexEntry},
    relocate::{Relocate, RelocationMap},
    strings::PackageStringTable,
    GarbageCollectionData, Session,
};

/// New-type'd index (constructed from `gimli::DwoId`) with a custom `Debug` implementation to
/// print in hexadecimal.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct DwoId(pub(crate) u64);

impl Bucketable for DwoId {
    fn index(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for DwoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DwoId({:#x})", self.0)
    }
}

impl From<gimli::DwoId> for DwoId {
    fn from(dwo_id: gimli::DwoId) -> Self {
        Self(dwo_id.0)
    }
}

/// New-type'd index (constructed from `gimli::DebugTypeSignature`) with a custom `Debug`
/// implementation to print in hexadecimal.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct DebugTypeSignature(pub(crate) u64);

impl Bucketable for DebugTypeSignature {
    fn index(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for DebugTypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DebugTypeSignature({:#x})", self.0)
    }
}

impl From<gimli::DebugTypeSignature> for DebugTypeSignature {
    fn from(signature: gimli::DebugTypeSignature) -> Self {
        Self(signature.0)
    }
}

/// Identifier for a DWARF object.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum DwarfObject {
    /// `DwoId` identifying compilation units.
    Compilation(DwoId),
    /// `DebugTypeSignature` identifying type units.
    Type(DebugTypeSignature),
}

impl Bucketable for DwarfObject {
    fn index(&self) -> u64 {
        match *self {
            DwarfObject::Compilation(dwo_id) => dwo_id.index(),
            DwarfObject::Type(type_signature) => type_signature.index(),
        }
    }
}

/// Returns the `DwoId` or `DebugTypeSignature` of a unit.
///
/// **DWARF 5:**
///
/// - `DwoId` is in the unit header of a skeleton unit (identifying the split compilation unit
/// that contains the debuginfo) or split compilation unit (identifying the skeleton unit that this
/// debuginfo corresponds to).
/// - `DebugTypeSignature` is in the unit header of a split type unit.
///
/// **Earlier DWARF versions with GNU extension:**
///
/// - `DW_AT_GNU_dwo_id` attribute of the DIE contains the `DwoId`.
#[tracing::instrument(level = "trace", skip(debug_abbrev, header))]
pub(crate) fn dwo_identifier_of_unit<R: gimli::Reader>(
    debug_abbrev: &gimli::DebugAbbrev<R>,
    header: &gimli::UnitHeader<R>,
) -> Result<Option<DwarfObject>> {
    match header.type_() {
        // Compilation units with DWARF 5
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => {
            Ok(Some(DwarfObject::Compilation(dwo_id.into())))
        }
        // Compilation units with GNU Extension
        UnitType::Compilation => {
            let abbreviations =
                header.abbreviations(debug_abbrev).map_err(Error::ParseUnitAbbreviations)?;
            let mut cursor = header.entries(&abbreviations);
            cursor.next_dfs()?;
            let root = cursor.current().ok_or(Error::NoDie)?;
            match root.tag() {
                gimli::DW_TAG_compile_unit | gimli::DW_TAG_type_unit => (),
                _ => return Err(Error::TopLevelDieNotUnit),
            }
            for attr in root.attrs() {
                if let (gimli::constants::DW_AT_GNU_dwo_id, gimli::AttributeValue::DwoId(dwo_id)) =
                    (attr.name(), attr.value())
                {
                    return Ok(Some(DwarfObject::Compilation(dwo_id.into())));
                }
            }

            Ok(None)
        }
        // Type units with DWARF 5
        UnitType::SplitType { type_signature, .. } => {
            Ok(Some(DwarfObject::Type(type_signature.into())))
        }
        // Type units with GNU extension
        UnitType::Type { type_signature, .. } => Ok(Some(DwarfObject::Type(type_signature.into()))),
        // Wrong compilation unit type.
        _ => Ok(None),
    }
}

/// Wrapper around `.debug_info.dwo` and `debug_types.dwo` unit iterators for uniform handling.
enum UnitHeaderIterator<R: gimli::Reader> {
    DebugInfo(gimli::read::DebugInfoUnitHeadersIter<R>),
    DebugTypes(gimli::read::DebugTypesUnitHeadersIter<R>),
}

impl<R: gimli::Reader> UnitHeaderIterator<R> {
    fn next(&mut self) -> gimli::read::Result<Option<UnitHeader<R>>> {
        match self {
            UnitHeaderIterator::DebugInfo(iter) => iter.next(),
            UnitHeaderIterator::DebugTypes(iter) => iter.next(),
        }
    }
}

/// Returns the parsed unit index from a `.debug_{cu,tu}_index` section.
pub(crate) fn maybe_load_index_section<'input, 'session: 'input, Endian, Index, R, Sess>(
    sess: &'session Sess,
    encoding: Encoding,
    endian: Endian,
    input: &object::File<'input>,
) -> Result<Option<UnitIndex<R>>>
where
    Endian: gimli::Endianity,
    Index: IndexSectionExt<'input, Endian, R>,
    R: gimli::Reader,
    Sess: Session<RelocationMap>,
{
    let index_name = Index::id().dwo_name().expect("index id w/out known value");
    if let Some(index_section) = input.section_by_name(index_name) {
        let index_data = index_section
            .compressed_data()
            .and_then(|d| d.decompress())
            .map_err(Error::DecompressData)?;
        let index_data_ref = sess.alloc_owned_cow(index_data);
        let unit_index = Index::new(index_data_ref, endian)
            .index()
            .map_err(|e| Error::ParseIndex(e, index_name.to_string()))?;

        if !encoding.is_compatible_dwarf_package_index_version(unit_index.version()) {
            return Err(Error::IncompatibleIndexVersion(
                index_name.to_string(),
                encoding.dwarf_package_index_version(),
                unit_index.version(),
            ));
        }

        Ok(Some(unit_index))
    } else {
        Ok(None)
    }
}

/// Returns a closure which takes an identifier and a `Option<Contribution>`, and returns an
/// adjusted contribution if the input file is a DWARF package (and the contribution was
/// present).
///
/// For example, consider the `.debug_str_offsets` section: DWARF packages have a single
/// `.debug_str_offsets` section which contains the string offsets of all of its compilation/type
/// units, the contributions of each unit into that section are tracked in its
/// `.debug_{cu,tu}_index` section.
///
/// When a DWARF package is the input, the contributions of the units which constituted that
/// package should not be lost when its `.debug_str_offsets` section is merged with the new
/// DWARF package currently being created.
///
/// Given a parsed index section, use the size of its contribution to `.debug_str_offsets` as the
/// size of its contribution in the new unit (without this, it would be the size of the entire
/// `.debug_str_offsets` section from the input, rather than the part that the compilation unit
/// originally contributed to that). For subsequent units from the input, the offset in the
/// contribution will need to be adjusted to based on the size of the previous units.
///
/// This function returns a "contribution adjustor" closure, which adjusts the contribution's
/// offset and size according to its contribution in the input's index and with an offset
/// accumulated over all calls to the closure.
pub(crate) fn create_contribution_adjustor<'input, R: 'input>(
    cu_index: Option<&'input UnitIndex<R>>,
    tu_index: Option<&'input UnitIndex<R>>,
    target_section_id: gimli::IndexSectionId,
) -> impl FnMut(DwarfObject, Option<Contribution>) -> Result<Option<Contribution>> + 'input
where
    R: gimli::Reader,
{
    let mut cu_adjustment = 0;
    let mut tu_adjustment = 0;

    move |identifier: DwarfObject,
          contribution: Option<Contribution>|
          -> Result<Option<Contribution>> {
        let (adjustment, index) = match identifier {
            DwarfObject::Compilation(_) => (&mut cu_adjustment, &cu_index),
            DwarfObject::Type(_) => (&mut tu_adjustment, &tu_index),
        };
        match (index, contribution) {
            // dwp input with section
            (Some(index), Some(contribution)) => {
                let section = find_index_section(index, identifier, target_section_id)?
                    .ok_or(Error::SectionNotInRow)?;
                let adjusted_offset: u64 = contribution.offset.0 + *adjustment;
                *adjustment += section.size as u64;

                Ok(Some(Contribution::from((adjusted_offset, section.size as u64))))
            }
            // dwp input without section
            (Some(_) | None, None) => Ok(contribution),
            // dwo input with section, but we aren't adjusting this particular index
            (None, Some(_)) => Ok(contribution),
        }
    }
}

/// Look up a unit's entry for the specified section in a `UnitIndex`.
fn find_index_section<R: gimli::Reader>(
    index: &UnitIndex<R>,
    id: DwarfObject,
    section_id: gimli::IndexSectionId,
) -> Result<Option<gimli::UnitIndexSection>> {
    let idx = id.index();
    let row_id = index.find(idx).ok_or(Error::UnitNotInIndex(idx))?;
    let section = index
        .sections(row_id)
        .map_err(|e| Error::RowNotInIndex(e, row_id))?
        .find(|index_section| index_section.section == section_id);
    Ok(section)
}

/// Resolve a unit's [`Contribution`] within a shared input section.
///
/// For `.dwp` inputs the range comes from the unit index. For `.dwo` inputs
/// (no index) the unit's contribution is the whole section, so a `Contribution`
/// covering the entire section is returned. This mirrors the per-unit slicing
/// done by `create_contribution_adjustor`, but is used by GC to rewrite each
/// unit's subrange of the section independently.
fn unit_section_range<R: gimli::Reader>(
    index: Option<&UnitIndex<R>>,
    id: DwarfObject,
    section_id: gimli::IndexSectionId,
    whole_len: usize,
) -> Result<Contribution> {
    let Some(index) = index else {
        return Ok(Contribution::from((0, whole_len)));
    };

    let section = find_index_section(index, id, section_id)?;
    let contribution = section.map_or(Contribution::default(), |s| {
        Contribution::from((s.offset as usize, s.size as usize))
    });
    // The offset and size come straight from the (possibly malformed) input index, so
    // validate them against the real section length before they are used to slice it.
    if contribution.offset.0.checked_add(contribution.size).is_none_or(|end| end > whole_len as u64)
    {
        return Err(Error::ContributionOutOfBounds(contribution, whole_len));
    }
    Ok(contribution)
}

/// Per-CU data accumulated during the first pass and carried forward
/// to output the shared sections.
///
/// `entry` is built incrementally: the non-shared fields are set during the
/// first pass, and the four shared fields (`debug_loc`, `debug_loclists`,
/// `debug_rnglists`, `debug_str_offsets`) are either filled in directly by
/// `emit_gc_shared_sections` (GC no-type-units path) or computed from
/// adjustors in the second pass (all other paths).
struct PendingEntry {
    entry: IndexEntry,
    /// GC result for this unit, used to rewrite shared sections.
    gc_result: Option<crate::gc::GcResult>,
}

/// Wrapper around `object::write::Object` that keeps track of the section indexes relevant to
/// DWARF packaging.
struct DwarfPackageObject<'file> {
    /// Object file being created.
    obj: WritableObject<'file>,

    /// Identifier for output `.debug_cu_index.dwo` section.
    debug_cu_index: Option<SectionId>,
    /// `.debug_tu_index.dwo`
    debug_tu_index: Option<SectionId>,
    /// `.debug_info.dwo`
    debug_info: Option<SectionId>,
    /// `.debug_abbrev.dwo`
    debug_abbrev: Option<SectionId>,
    /// `.debug_str.dwo`
    debug_str: Option<SectionId>,
    /// `.debug_types.dwo`
    debug_types: Option<SectionId>,
    /// `.debug_line.dwo`
    debug_line: Option<SectionId>,
    /// `.debug_loc.dwo`
    debug_loc: Option<SectionId>,
    /// `.debug_loclists.dwo`
    debug_loclists: Option<SectionId>,
    /// `.debug_rnglists.dwo`
    debug_rnglists: Option<SectionId>,
    /// `.debug_str_offsets.dwo`
    debug_str_offsets: Option<SectionId>,
    /// `.debug_macinfo.dwo`
    debug_macinfo: Option<SectionId>,
    /// `.debug_macro.dwo`
    debug_macro: Option<SectionId>,
}

/// Macro for generating helper functions which appending non-empty data to specific sections.
macro_rules! generate_append_for {
    ( $( $fn_name:ident => ($name:ident, $section_name:expr) ),+ ) => {
        $(
            fn $fn_name(&mut self, data: &[u8]) -> Option<Contribution> {
                if data.is_empty() {
                    return None;
                }

                let id = *self.$name.get_or_insert_with(|| self.obj.add_section(
                    Vec::new(),
                    Vec::from($section_name),
                    SectionKind::Debug,
                ));

                // FIXME: correct alignment
                let offset = self.obj.append_section_data(id, data, 1);
                debug!(?offset, ?data);
                Some(Contribution::from((offset, data.len().try_into().expect("data size larger than u64"))))
            }
        )+
    };
}

impl<'file> DwarfPackageObject<'file> {
    /// Create a new `DwarfPackageObject` from an architecture and endianness.
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(
        architecture: object::Architecture,
        endianness: object::Endianness,
    ) -> DwarfPackageObject<'file> {
        let obj = WritableObject::new(BinaryFormat::Elf, architecture, endianness);
        Self {
            obj,
            debug_cu_index: Default::default(),
            debug_tu_index: Default::default(),
            debug_info: Default::default(),
            debug_abbrev: Default::default(),
            debug_str: Default::default(),
            debug_types: Default::default(),
            debug_line: Default::default(),
            debug_loc: Default::default(),
            debug_loclists: Default::default(),
            debug_rnglists: Default::default(),
            debug_str_offsets: Default::default(),
            debug_macinfo: Default::default(),
            debug_macro: Default::default(),
        }
    }

    generate_append_for! {
        append_to_debug_abbrev => (debug_abbrev, ".debug_abbrev.dwo"),
        append_to_debug_cu_index => (debug_cu_index, ".debug_cu_index"),
        append_to_debug_info => (debug_info, ".debug_info.dwo"),
        append_to_debug_line => (debug_line, ".debug_line.dwo"),
        append_to_debug_loc => (debug_loc, ".debug_loc.dwo"),
        append_to_debug_loclists => (debug_loclists, ".debug_loclists.dwo"),
        append_to_debug_macinfo => (debug_macinfo, ".debug_macinfo.dwo"),
        append_to_debug_macro => (debug_macro, ".debug_macro.dwo"),
        append_to_debug_rnglists => (debug_rnglists, ".debug_rnglists.dwo"),
        append_to_debug_str => (debug_str, ".debug_str.dwo"),
        append_to_debug_str_offsets => (debug_str_offsets, ".debug_str_offsets.dwo"),
        append_to_debug_tu_index => (debug_tu_index, ".debug_tu_index"),
        append_to_debug_types => (debug_types, ".debug_types.dwo")
    }

    /// Return the DWARF package object file.
    pub(crate) fn finish(self) -> WritableObject<'file> {
        self.obj
    }
}

pub(crate) struct GcSessionData<'input, 'gc, 'session, Sess>
where
    Sess: Session<RelocationMap>,
{
    session: &'session Sess,
    gc_data: &'gc GarbageCollectionData<'session>,
    debug_loc: Cow<'input, [u8]>,
    debug_loclists: Cow<'input, [u8]>,
    debug_rnglists: Cow<'input, [u8]>,
    debug_str_offsets: gimli::DebugStrOffsets<gimli::EndianSlice<'input, RunTimeEndian>>,
    debug_str: gimli::DebugStr<gimli::EndianSlice<'input, RunTimeEndian>>,
}

pub(crate) enum SessionHolder<'input, 'gc, 'session, Sess>
where
    Sess: Session<RelocationMap>,
{
    SimpleSession(&'session Sess),
    GcSession(GcSessionData<'input, 'gc, 'session, Sess>),
}

impl<'input, 'gc, 'session, Sess> SessionHolder<'input, 'gc, 'session, Sess>
where
    Sess: Session<RelocationMap>,
{
    fn session(&'_ self) -> &'session Sess {
        match self {
            SessionHolder::SimpleSession(session)
            | SessionHolder::GcSession(GcSessionData { session, .. }) => session,
        }
    }

    fn save_debug_loc_for_gc(&mut self, debug_loc: Cow<'input, [u8]>) -> Option<Cow<'input, [u8]>> {
        let SessionHolder::GcSession(ref mut data) = self else {
            return Some(debug_loc);
        };

        data.debug_loc = debug_loc;
        None
    }

    fn save_debug_loclists_for_gc(
        &mut self,
        debug_loclists: Cow<'input, [u8]>,
    ) -> Option<Cow<'input, [u8]>> {
        let SessionHolder::GcSession(ref mut data) = self else {
            return Some(debug_loclists);
        };

        data.debug_loclists = debug_loclists;
        None
    }

    fn save_debug_rnglists_for_gc(
        &mut self,
        debug_rnglists: Cow<'input, [u8]>,
    ) -> Option<Cow<'input, [u8]>> {
        let SessionHolder::GcSession(ref mut data) = self else {
            return Some(debug_rnglists);
        };

        data.debug_rnglists = debug_rnglists;
        None
    }

    fn save_debug_str_offsets_for_gc(
        &mut self,
        debug_str_offsets: gimli::DebugStrOffsets<gimli::EndianSlice<'input, RunTimeEndian>>,
    ) -> bool {
        let SessionHolder::GcSession(ref mut data) = self else {
            return false;
        };

        data.debug_str_offsets = debug_str_offsets;
        true
    }

    fn save_debug_str_for_gc(
        &mut self,
        debug_str: gimli::DebugStr<gimli::EndianSlice<'input, RunTimeEndian>>,
    ) -> bool {
        let SessionHolder::GcSession(ref mut data) = self else {
            return false;
        };

        data.debug_str = debug_str;
        true
    }
}

impl<'input, 'gc, 'session: 'input, S: Session<RelocationMap>>
    SessionHolder<'input, 'gc, 'session, S>
{
    fn maybe_gc<R: gimli::Reader>(
        data: &GcSessionData<'input, 'gc, 'session, S>,
        cu_index: Option<&UnitIndex<R>>,
        id: DwarfObject,
        debug_info: &'input [u8],
        debug_abbrev: &gimli::DebugAbbrev<gimli::EndianSlice<'input, RunTimeEndian>>,
        endian: RunTimeEndian,
        has_type_units: bool,
    ) -> Result<Option<crate::gc::GcResult>> {
        let DwarfObject::Compilation(dwo_id) = id else {
            return Ok(None);
        };
        let Some(exec_entries) = data.gc_data.get_data_for_dwo(dwo_id) else {
            return Ok(None);
        };
        debug_assert!(!exec_entries.is_empty());

        // The DWARF4 `.debug_ranges` contains addresses separately from the
        // `.debug_addr` section. Rather than implement the `.debug_addr` style
        // merging we do with is_addr_live below for cases with more than one
        // executable with `.debug_ranges`, just error out to avoid the
        // complexity of handling an extreme edge case.
        if exec_entries
            .iter()
            .filter(|(exec, _)| !exec.0.ranges.debug_ranges().reader().is_empty())
            .count()
            > 1
        {
            return Err(crate::error::Error::GcSharedDwarf4Ranges(dwo_id));
        }

        let is_addr_live = |index: gimli::DebugAddrIndex<usize>| -> crate::error::Result<bool> {
            for (executable_data, dwo_data) in &exec_entries {
                let addr = executable_data
                    .0
                    .debug_addr
                    .get_address(dwo_data.addr_size, dwo_data.addr_base, index)
                    .map_err(crate::error::Error::from)?;
                if !is_tombstone(addr, dwo_data.addr_size) {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        // For `.dwp` inputs the shared sections are concatenations of per-CU
        // contributions, and the CU header's offsets (e.g. abbrev) are relative
        // to this CU's contribution. Slice each section to this CU's subrange
        // so the DIE walk resolves abbreviations, location lists,
        // and range lists correctly (for `.dwo` inputs each subrange is the
        // whole section and this is a noop).
        let abbrev_bytes = debug_abbrev.reader().slice();
        let abbrev_contribution = unit_section_range(
            cu_index,
            id,
            gimli::IndexSectionId::DebugAbbrev,
            abbrev_bytes.len(),
        )?;
        let debug_abbrev =
            gimli::DebugAbbrev::new(&abbrev_bytes[abbrev_contribution.range()], endian);

        let loc_contribution = unit_section_range(
            cu_index,
            id,
            gimli::IndexSectionId::DebugLoc,
            data.debug_loc.len(),
        )?;
        let loclists_contribution = unit_section_range(
            cu_index,
            id,
            gimli::IndexSectionId::DebugLocLists,
            data.debug_loclists.len(),
        )?;
        let rnglists_contribution = unit_section_range(
            cu_index,
            id,
            gimli::IndexSectionId::DebugRngLists,
            data.debug_rnglists.len(),
        )?;

        // `.debug_rnglists` data in the .dwo is self-contained; only the
        // executable's `.debug_ranges` is needed to construct `RangeLists`.
        // At most one executable has non-empty `.debug_ranges` here (enforced
        // above), so use that one. If none do, just take the first one since
        // it's unused.
        let ranges_idx = exec_entries
            .iter()
            .position(|(exec, _)| !exec.0.ranges.debug_ranges().reader().is_empty())
            .unwrap_or(0);
        let ranges_executable_data = &exec_entries[ranges_idx].0;
        let ranges_base = exec_entries[ranges_idx].1.ranges_base;

        let gc_result = crate::gc::gc_debug_info(
            gimli::DebugInfo::new(debug_info, endian),
            debug_abbrev,
            gimli::LocationLists::new(
                gimli::DebugLoc::from(gimli::EndianSlice::new(
                    &data.debug_loc[loc_contribution.range()],
                    endian,
                )),
                gimli::DebugLocLists::from(gimli::EndianSlice::new(
                    &data.debug_loclists[loclists_contribution.range()],
                    endian,
                )),
            ),
            gimli::RangeLists::new(ranges_executable_data.0.ranges.debug_ranges().clone(), {
                let relocations = data.session.alloc_relocation(RelocationMap::default());
                let section = gimli::EndianSlice::new(
                    &data.debug_rnglists[rnglists_contribution.range()],
                    endian,
                );
                let reader = section;
                gimli::DebugRngLists::from(Relocate { relocations, section, reader })
            }),
            ranges_base,
            is_addr_live,
            dwo_id,
            has_type_units,
        )?;

        Ok(Some(gc_result))
    }

    /// Run garbage collection for a single unit. The shared per-input-object
    /// sections will be emitted once after all units have been GC'd by
    /// `emit_gc_shared_sections`. Returns the unit's [`crate::gc::GcResult`],
    /// if any.
    fn run_unit_gc<R: gimli::Reader>(
        &self,
        cu_index: Option<&UnitIndex<R>>,
        id: DwarfObject,
        debug_info: &'input [u8],
        debug_abbrev: &gimli::DebugAbbrev<gimli::EndianSlice<'input, RunTimeEndian>>,
        endian: RunTimeEndian,
        has_type_units: bool,
    ) -> Result<Option<crate::gc::GcResult>> {
        let SessionHolder::GcSession(ref data) = self else {
            return Ok(None);
        };
        Self::maybe_gc(data, cu_index, id, debug_info, debug_abbrev, endian, has_type_units)
    }

    /// Emit the per-input-object shared sections (`.debug_rnglists`,
    /// `.debug_loc`, `.debug_loclists`, `.debug_str_offsets`) once,
    /// using the GC results of *all* units.
    ///
    /// These sections are shared between the units of an input object (in
    /// particular, a type unit shares them with its compilation unit, and a
    /// `.dwp` shares them across CUs), so they cannot be emitted inside the
    /// per-unit loop.
    /// Each unit's contribution to a shared section is rewritten independently
    /// using that unit's GC result and its own subrange of the section so
    /// CU-relative references and referenced-index sets from different units
    /// never bleed together.
    ///
    /// There are two regimes, selected by `has_type_units`:
    ///
    /// - **No type units**: list pruning is possible, so the rewritten bytes
    ///   may shrink. Each CU's subrange is rewritten, the chunks are
    ///   concatenated, and per-unit contributions are recomputed from the
    ///   actual chunk sizes. The returned map supplies these contributions
    ///   directly (the caller must not run the input-index-derived adjustors
    ///   for these sections). This method returns `Ok(true)` indicating that
    ///   it did the work.
    /// - **Type units present**: pruning is disabled, so only size-preserving
    ///   expression patching happens. Each CU's subrange is patched in place,
    ///   the byte layout is unchanged, and the base contributions are stored in
    ///   `debug_*`. The caller runs the normal adjustors and this method returns
    ///   `Ok(false)`.
    ///
    /// For a non-GC session this is a no-op returning `Ok(false)` (the shared
    /// sections were already appended in the section loop).
    fn emit_gc_shared_sections<R: gimli::Reader>(
        &self,
        cu_index: Option<&UnitIndex<R>>,
        pending: &mut [PendingEntry],
        encoding: Encoding,
        endian: RunTimeEndian,
        has_type_units: bool,
        has_debug_macro: bool,
        obj: &mut DwarfPackageObject<'_>,
        string_table: &mut PackageStringTable,
        debug_loc: &mut Option<Contribution>,
        debug_loclists: &mut Option<Contribution>,
        debug_rnglists: &mut Option<Contribution>,
        debug_str_offsets: &mut Option<Contribution>,
    ) -> Result<bool> {
        let SessionHolder::GcSession(ref data) = self else {
            return Ok(false);
        };

        if has_type_units {
            // Pruning is disabled. Patch CU-relative references in place, preserving the
            // exact byte layout so input-index-derived contributions remain valid.
            let str_offsets_whole = data.debug_str_offsets.reader().slice();
            let mut unit_has_loc: Vec<Contribution> = Vec::with_capacity(pending.len());
            let mut unit_has_loclists: Vec<Contribution> = Vec::with_capacity(pending.len());
            let mut unit_has_str_off: Vec<Contribution> = Vec::with_capacity(pending.len());
            match cu_index {
                None => {
                    for _ in pending.iter() {
                        unit_has_loc.push(Contribution::from((0, data.debug_loc.len())));
                        unit_has_loclists.push(Contribution::from((0, data.debug_loclists.len())));
                        unit_has_str_off.push(Contribution::from((0, str_offsets_whole.len())));
                    }
                }
                Some(index) => {
                    for unit in pending.iter() {
                        let id = unit.entry.id;
                        let idx = id.index();
                        let row_id = index.find(idx).ok_or(Error::UnitNotInIndex(idx))?;
                        let mut loc = Contribution::default();
                        let mut loclists = Contribution::default();
                        let mut str_off = Contribution::default();
                        for section in
                            index.sections(row_id).map_err(|e| Error::RowNotInIndex(e, row_id))?
                        {
                            let r = Contribution::from((section.offset, section.size));
                            match section.section {
                                gimli::IndexSectionId::DebugLoc => loc = r,
                                gimli::IndexSectionId::DebugLocLists => loclists = r,
                                gimli::IndexSectionId::DebugStrOffsets => str_off = r,
                                _ => {}
                            }
                        }
                        unit_has_loc.push(loc);
                        unit_has_loclists.push(loclists);
                        unit_has_str_off.push(str_off);
                    }
                }
            }

            if !data.debug_loc.is_empty() {
                let original = &data.debug_loc;
                let mut buf: Option<Vec<u8>> = None;
                for (idx, unit) in pending.iter().enumerate() {
                    let DwarfObject::Compilation(_) = unit.entry.id else { continue };
                    let Some(gc) = &unit.gc_result else { continue };
                    let Some(remap) = gc.rewritten.as_ref().and(gc.offset_remap.as_ref()) else {
                        continue;
                    };
                    let contribution = unit_has_loc[idx];
                    if contribution.size == 0 {
                        continue;
                    }
                    let bytes = buf.get_or_insert_with(|| original.to_vec());
                    if let Some(patched) = crate::gc::patch_debug_loc(
                        gimli::EndianSlice::new(&bytes[contribution.range()], endian),
                        encoding,
                        remap,
                    )? {
                        bytes[contribution.range()].copy_from_slice(&patched);
                    }
                }
                *debug_loc = obj.append_to_debug_loc(buf.as_deref().unwrap_or(original));
            }

            if !data.debug_loclists.is_empty() {
                let original = &data.debug_loclists;
                let mut buf: Option<Vec<u8>> = None;
                for (idx, unit) in pending.iter().enumerate() {
                    let DwarfObject::Compilation(_) = unit.entry.id else { continue };
                    let Some(gc) = &unit.gc_result else { continue };
                    let Some(remap) = gc.rewritten.as_ref().and(gc.offset_remap.as_ref()) else {
                        continue;
                    };
                    let contribution = unit_has_loclists[idx];
                    if contribution.size == 0 {
                        continue;
                    }
                    let bytes = buf.get_or_insert_with(|| original.to_vec());
                    if let Some(patched) = crate::gc::rewrite_loclists(
                        gimli::EndianSlice::new(&bytes[contribution.range()], endian),
                        None,
                        Some(remap),
                    )? {
                        bytes[contribution.range()].copy_from_slice(&patched);
                    }
                }
                *debug_loclists = obj.append_to_debug_loclists(buf.as_deref().unwrap_or(original));
            }

            // Range lists carry no DIE references and are not pruned when type units are present.
            if !data.debug_rnglists.is_empty() {
                *debug_rnglists = obj.append_to_debug_rnglists(&data.debug_rnglists);
            }

            // String offsets are never pruned here (no type-unit-safe compaction), but each CU's
            // contribution must still be remapped into the merged string table. Remap per-CU and
            // write back in place, so multi-CU DWARF 5 inputs (one header per contribution) are
            // handled correctly while the exact byte layout (and thus the adjustors) is preserved.
            // Type units share their compilation unit's contribution, so only compilation units
            // are iterated, remapping each distinct contribution exactly once.
            if !str_offsets_whole.is_empty() {
                let mut bytes = str_offsets_whole.to_vec();
                for (idx, unit) in pending.iter().enumerate() {
                    let DwarfObject::Compilation(_) = unit.entry.id else { continue };
                    let contribution = unit_has_str_off[idx];
                    if contribution.size == 0 {
                        continue;
                    }
                    let sub_str_offsets = gimli::DebugStrOffsets::from(gimli::EndianSlice::new(
                        &bytes[contribution.range()],
                        endian,
                    ));
                    let remapped = string_table.remap_str_offsets_section(
                        data.debug_str,
                        sub_str_offsets,
                        endian,
                        encoding,
                        None,
                    )?;
                    let remapped = remapped.slice();
                    assert_eq!(
                        remapped.len(),
                        contribution.size as usize,
                        "unpruned str_offsets remap must preserve contribution size"
                    );
                    bytes[contribution.range()].copy_from_slice(remapped);
                }
                *debug_str_offsets = obj.append_to_debug_str_offsets(&bytes);
            }

            return Ok(false);
        }

        // No type units: list pruning is possible, so rewrite each CU's subrange and write the
        // recomputed per-unit contributions directly into each pending entry.

        // Records each unit's `(start, len)` chunk within the freshly appended section directly
        // into the corresponding `pending` entry. `ranges` entries are `(pending_index, start, len)`.
        fn record(
            pending: &mut [PendingEntry],
            base: Option<Contribution>,
            ranges: &[(usize, usize, usize)],
            field: impl Fn(&mut IndexEntry) -> &mut Option<Contribution>,
        ) {
            let Some(base) = base else { return };
            for &(idx, start, len) in ranges {
                if len > 0 {
                    *field(&mut pending[idx].entry) = Some(Contribution {
                        offset: ContributionOffset(base.offset.0 + start as u64),
                        size: len as u64,
                    });
                }
            }
        }

        // Assembles output bytes from per-unit rewritten chunks (or the original section bytes),
        // appends to the output object, and records contributions into pending entries.
        fn assemble_and_record<FA, FF>(
            pending: &mut [PendingEntry],
            whole: &[u8],
            unit_ranges: &[Contribution],
            modified: Option<Vec<(usize, Vec<u8>)>>,
            mut append: FA,
            field: FF,
        ) where
            FA: FnMut(&[u8]) -> Option<Contribution>,
            FF: Fn(&mut IndexEntry) -> &mut Option<Contribution>,
        {
            let (base, ranges) = if let Some(modified) = modified {
                let modified: HashMap<usize, Vec<u8>> = modified.into_iter().collect();
                let mut bytes = Vec::new();
                let mut ranges: Vec<(usize, usize, usize)> = Vec::new();
                for (idx, _) in pending.iter().enumerate() {
                    let chunk: &[u8] = if let Some(v) = modified.get(&idx) {
                        v
                    } else {
                        &whole[unit_ranges[idx].range()]
                    };
                    let start = bytes.len();
                    bytes.extend_from_slice(chunk);
                    ranges.push((idx, start, chunk.len()));
                }
                (append(&bytes), ranges)
            } else {
                let ranges = unit_ranges
                    .iter()
                    .enumerate()
                    .map(|(idx, c)| (idx, c.offset.0 as usize, c.size as usize))
                    .collect();
                (append(whole), ranges)
            };
            record(pending, base, &ranges, field);
        }

        // Pre-compute each unit's (offset, size) for all four shared sections in a single
        // index lookup per unit: one index.find + one sections scan covers all four sections,
        // rather than four separate unit_section_range calls (each doing their own find + scan).
        let str_offsets_whole = data.debug_str_offsets.reader().slice();
        let mut unit_rnglists: Vec<Contribution> = Vec::with_capacity(pending.len());
        let mut unit_loc: Vec<Contribution> = Vec::with_capacity(pending.len());
        let mut unit_loclists: Vec<Contribution> = Vec::with_capacity(pending.len());
        let mut unit_str_offsets: Vec<Contribution> = Vec::with_capacity(pending.len());
        for unit in pending.iter() {
            let (rng, loc, loclists, str_off) = match cu_index {
                None => (
                    Contribution::from((0, data.debug_rnglists.len())),
                    Contribution::from((0, data.debug_loc.len())),
                    Contribution::from((0, data.debug_loclists.len())),
                    Contribution::from((0, str_offsets_whole.len())),
                ),
                Some(index) => {
                    let id = unit.entry.id;
                    let idx = id.index();
                    let row_id = index.find(idx).ok_or(Error::UnitNotInIndex(idx))?;
                    let mut rng = Contribution::default();
                    let mut loc = Contribution::default();
                    let mut loclists = Contribution::default();
                    let mut str_off = Contribution::default();
                    for section in
                        index.sections(row_id).map_err(|e| Error::RowNotInIndex(e, row_id))?
                    {
                        let r = Contribution::from((section.offset, section.size));
                        match section.section {
                            gimli::IndexSectionId::DebugRngLists => rng = r,
                            gimli::IndexSectionId::DebugLoc => loc = r,
                            gimli::IndexSectionId::DebugLocLists => loclists = r,
                            gimli::IndexSectionId::DebugStrOffsets => str_off = r,
                            _ => {}
                        }
                    }
                    (rng, loc, loclists, str_off)
                }
            };
            unit_rnglists.push(rng);
            unit_loc.push(loc);
            unit_loclists.push(loclists);
            unit_str_offsets.push(str_off);
        }

        if !data.debug_rnglists.is_empty() {
            let whole = &data.debug_rnglists;
            // Collect only the units whose rnglists were actually rewritten. In the common case
            // (no rewriting) this stays None and no extra allocation is needed.
            let mut modified: Option<Vec<(usize, Vec<u8>)>> = None;
            for (idx, unit) in pending.iter().enumerate() {
                let contribution = unit_rnglists[idx];
                if contribution.size == 0 {
                    continue;
                }
                let Some(gc) = &unit.gc_result else { continue };
                let Some(referenced) = gc.rewritten.as_ref().and(gc.referenced_rnglists.as_ref())
                else {
                    continue;
                };
                let DwarfObject::Compilation(dwo_id) = unit.entry.id else {
                    unreachable!("rnglists referenced set is only set for compilation units")
                };
                let Some(exec_entries) = data.gc_data.get_data_for_dwo(dwo_id) else {
                    continue;
                };
                let is_addr_live =
                    |index: gimli::DebugAddrIndex<usize>| -> crate::error::Result<bool> {
                        for (executable_data, dwo_data) in &exec_entries {
                            let addr = executable_data
                                .0
                                .debug_addr
                                .get_address(dwo_data.addr_size, dwo_data.addr_base, index)
                                .map_err(crate::error::Error::from)?;
                            if !is_tombstone(addr, dwo_data.addr_size) {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    };
                if let Some(v) = crate::gc::rewrite_rnglists(
                    gimli::EndianSlice::new(&whole[contribution.range()], endian),
                    referenced,
                    &is_addr_live,
                    dwo_id,
                )? {
                    modified.get_or_insert_with(Vec::new).push((idx, v));
                }
            }
            assemble_and_record(
                pending,
                whole,
                &unit_rnglists,
                modified,
                |b| obj.append_to_debug_rnglists(b),
                |e| &mut e.debug_rnglists,
            );
        }

        if !data.debug_loc.is_empty() {
            let whole = &data.debug_loc;
            let mut modified: Option<Vec<(usize, Vec<u8>)>> = None;
            for (idx, unit) in pending.iter().enumerate() {
                let contribution = unit_loc[idx];
                if contribution.size == 0 {
                    continue;
                }
                let Some(gc) = &unit.gc_result else { continue };
                let Some(remap) = gc.rewritten.as_ref().and(gc.offset_remap.as_ref()) else {
                    continue;
                };
                if let Some(v) = crate::gc::patch_debug_loc(
                    gimli::EndianSlice::new(&whole[contribution.range()], endian),
                    encoding,
                    remap,
                )? {
                    modified.get_or_insert_with(Vec::new).push((idx, v));
                }
            }
            assemble_and_record(
                pending,
                whole,
                &unit_loc,
                modified,
                |b| obj.append_to_debug_loc(b),
                |e| &mut e.debug_loc,
            );
        }

        if !data.debug_loclists.is_empty() {
            let whole = &data.debug_loclists;
            let mut modified: Option<Vec<(usize, Vec<u8>)>> = None;
            for (idx, unit) in pending.iter().enumerate() {
                let contribution = unit_loclists[idx];
                if contribution.size == 0 {
                    continue;
                }
                let Some(gc) = &unit.gc_result else { continue };
                let remap = gc.rewritten.as_ref().and(gc.offset_remap.as_ref());
                if remap.is_some() {
                    if let Some(v) = crate::gc::rewrite_loclists(
                        gimli::EndianSlice::new(&whole[contribution.range()], endian),
                        gc.rewritten.as_ref().and(gc.referenced_loclists.as_ref()),
                        remap,
                    )? {
                        modified.get_or_insert_with(Vec::new).push((idx, v));
                    }
                }
            }
            assemble_and_record(
                pending,
                whole,
                &unit_loclists,
                modified,
                |b| obj.append_to_debug_loclists(b),
                |e| &mut e.debug_loclists,
            );
        }

        if !str_offsets_whole.is_empty() {
            // Count how many pending units share each contribution range. When cu_index=None
            // every unit gets (0, whole_len), so all CUs share one range. In that case the
            // per-CU strx filter cannot be applied safely: the filter indices are 0-based
            // within each CU's own sub-table, but the slice starts at offset 0 of the
            // full section (i.e. the first CU's territory). Use filter=None for any range
            // that is shared, preserving all entries.
            let mut range_count: HashMap<Contribution, usize> = HashMap::new();
            for &contribution in &unit_str_offsets {
                if contribution.size > 0 {
                    *range_count.entry(contribution).or_insert(0) += 1;
                }
            }

            let mut bytes = Vec::new();
            let mut ranges = Vec::new();
            // Cache contribution → (start, len) in `bytes` so units sharing a range
            // reuse the same remapped bytes rather than re-remapping (which would be
            // wrong for per-CU filters and wasteful even for filter=None).
            let mut range_cache: HashMap<Contribution, (usize, usize)> = HashMap::new();
            for (idx, unit) in pending.iter().enumerate() {
                let contribution = unit_str_offsets[idx];
                if contribution.size == 0 {
                    continue;
                }
                if let Some(&(start, len)) = range_cache.get(&contribution) {
                    ranges.push((idx, start, len));
                    continue;
                }
                // A `.debug_macro` section indexes strings by `strx`, so the offset table cannot
                // be compacted even when DIEs are removed. Likewise, when this contribution range
                // is shared by multiple units (cu_index=None, multi-CU .dwo), per-CU filtering
                // cannot be applied correctly.
                let filter = if has_debug_macro
                    || range_count.get(&contribution).copied().unwrap_or(0) > 1
                {
                    None
                } else {
                    unit.gc_result.as_ref().and_then(|gc| {
                        gc.rewritten.as_ref().and(gc.referenced_str_offsets.as_ref())
                    })
                };
                let sub_str_offsets = gimli::DebugStrOffsets::from(gimli::EndianSlice::new(
                    &str_offsets_whole[contribution.range()],
                    endian,
                ));
                let remapped = string_table.remap_str_offsets_section(
                    data.debug_str,
                    sub_str_offsets,
                    endian,
                    encoding,
                    filter,
                )?;
                let start = bytes.len();
                bytes.extend_from_slice(remapped.slice());
                let len = bytes.len() - start;
                range_cache.insert(contribution, (start, len));
                ranges.push((idx, start, len));
            }
            let base = obj.append_to_debug_str_offsets(&bytes);
            record(pending, base, &ranges, |e| &mut e.debug_str_offsets);
        }

        Ok(true)
    }

    pub(crate) fn new_gc(sess: &'session S, gc_data: &'gc GarbageCollectionData<'session>) -> Self {
        SessionHolder::GcSession(GcSessionData {
            session: sess,
            gc_data,
            debug_loc: Default::default(),
            debug_loclists: Default::default(),
            debug_rnglists: Default::default(),
            debug_str_offsets: Default::default(),
            debug_str: Default::default(),
        })
    }
}

/// In-progress DWARF package being produced.
pub(crate) struct InProgressDwarfPackage<'file> {
    /// Endianness of the DWARF package being created.
    endian: RunTimeEndian,

    /// Object file being created.
    obj: DwarfPackageObject<'file>,
    /// In-progress string table being accumulated.
    ///
    /// Used to write final `.debug_str.dwo` and `.debug_str_offsets.dwo`.
    string_table: PackageStringTable,

    /// Compilation unit index entries (offsets + sizes) being accumulated.
    cu_index_entries: Vec<IndexEntry>,
    /// Type unit index entries (offsets + sizes) being accumulated.
    tu_index_entries: Vec<IndexEntry>,

    /// `DebugTypeSignature`s of type units and `DwoId`s of compilation units that have already
    /// been added to the output package.
    ///
    /// Used when adding new TU index entries to de-duplicate type units (as required by the
    /// specification). Also used to check that all dwarf objects referenced by executables
    /// have been found.
    contained_units: HashSet<DwarfObject>,
}

impl<'file> InProgressDwarfPackage<'file> {
    /// Create an object file with empty sections that will be later populated from DWARF object
    /// files.
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(
        architecture: object::Architecture,
        endianness: object::Endianness,
    ) -> InProgressDwarfPackage<'file> {
        let endian = endianness.as_runtime_endian();
        Self {
            endian,
            obj: DwarfPackageObject::new(architecture, endianness),
            string_table: PackageStringTable::new(),
            cu_index_entries: Default::default(),
            tu_index_entries: Default::default(),
            contained_units: Default::default(),
        }
    }

    /// Returns the units contained within the DWARF package.
    pub(crate) fn contained_units(&self) -> &HashSet<DwarfObject> {
        &self.contained_units
    }

    /// Process an input DWARF object.
    ///
    /// Copies relevant debug sections, compilation/type units and strings from the `input` DWARF
    /// object into this DWARF package.
    #[tracing::instrument(level = "trace", skip(sess, input))]
    pub(crate) fn add_input_object<'input, 'gc, 'session: 'input>(
        &mut self,
        mut sess: SessionHolder<'input, 'gc, 'session, impl Session<RelocationMap>>,
        input: &object::File<'input>,
        encoding: Encoding,
    ) -> Result<()> {
        // Load index sections (if they exist).
        let cu_index = maybe_load_index_section::<_, gimli::DebugCuIndex<_>, _, _>(
            sess.session(),
            encoding,
            self.endian,
            input,
        )?;
        let tu_index = maybe_load_index_section::<_, gimli::DebugTuIndex<_>, _, _>(
            sess.session(),
            encoding,
            self.endian,
            input,
        )?;

        let mut debug_abbrev = None;
        let mut debug_line = None;
        let mut debug_loc = None;
        let mut debug_loclists = None;
        let mut debug_macinfo = None;
        let mut debug_macro = None;
        let mut debug_rnglists = None;
        let mut debug_str_offsets = None;

        macro_rules! update {
            ($target:ident += $source:expr) => {
                if let Some(other) = $source {
                    let contribution = $target.get_or_insert(Contribution { size: 0, ..other });
                    contribution.size += other.size;
                }
                debug!(?$target);
            };
        }

        // Iterate over sections rather than using `section_by_name` because sections can be
        // repeated.
        let mut has_type_units = false;
        for section in input.sections() {
            match section.name() {
                Ok(".debug_abbrev.dwo" | ".zdebug_abbrev.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    update!(debug_abbrev += self.obj.append_to_debug_abbrev(&data));
                }
                Ok(".debug_line.dwo" | ".zdebug_line.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    update!(debug_line += self.obj.append_to_debug_line(&data));
                }
                Ok(".debug_loc.dwo" | ".zdebug_loc.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    if let Some(data) = sess.save_debug_loc_for_gc(data) {
                        update!(debug_loc += self.obj.append_to_debug_loc(&data));
                    }
                }
                Ok(".debug_loclists.dwo" | ".zdebug_loclists.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    if let Some(data) = sess.save_debug_loclists_for_gc(data) {
                        update!(debug_loclists += self.obj.append_to_debug_loclists(&data));
                    }
                }
                Ok(".debug_macinfo.dwo" | ".zdebug_macinfo.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    update!(debug_macinfo += self.obj.append_to_debug_macinfo(&data));
                }
                Ok(".debug_macro.dwo" | ".zdebug_macro.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    update!(debug_macro += self.obj.append_to_debug_macro(&data));
                }
                Ok(".debug_rnglists.dwo" | ".zdebug_rnglists.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    if let Some(data) = sess.save_debug_rnglists_for_gc(data) {
                        update!(debug_rnglists += self.obj.append_to_debug_rnglists(&data));
                    }
                }
                Ok(".debug_str_offsets.dwo" | ".zdebug_str_offsets.dwo") => {
                    let data = section.compressed_data()?.decompress()?;
                    let data_ref = sess.session().alloc_owned_cow(data);

                    let debug_str_offsets_section = gimli::DebugStrOffsets::from(
                        gimli::EndianSlice::new(data_ref, self.endian),
                    );
                    let debug_str_section =
                        if let Some(str_section) = input.section_by_name(".debug_str.dwo") {
                            let str_data = str_section.compressed_data()?.decompress()?;
                            let str_data_ref = sess.session().alloc_owned_cow(str_data);
                            gimli::DebugStr::new(str_data_ref, self.endian)
                        } else {
                            return Err(Error::MissingRequiredSection(".debug_str.dwo"));
                        };
                    let saved_offsets =
                        sess.save_debug_str_offsets_for_gc(debug_str_offsets_section);
                    let saved_str = sess.save_debug_str_for_gc(debug_str_section);
                    if !saved_offsets && !saved_str {
                        let remapped = self.string_table.remap_str_offsets_section(
                            debug_str_section,
                            debug_str_offsets_section,
                            self.endian,
                            encoding,
                            None,
                        )?;
                        update!(
                            debug_str_offsets +=
                                self.obj.append_to_debug_str_offsets(remapped.slice())
                        );
                    }
                }
                Ok(".debug_types.dwo" | ".zdebug_types.dwo") => {
                    has_type_units = true;
                }
                _ => (),
            }
        }

        // `.debug_abbrev.dwo`'s contribution will already have been processed, but getting the
        // `DwoId` of a GNU Extension compilation unit requires access to it.
        let debug_abbrev_section = if let Some(section) = input.section_by_name(".debug_abbrev.dwo")
        {
            let data = section.compressed_data()?.decompress()?;
            let data_ref = sess.session().alloc_owned_cow(data);
            gimli::DebugAbbrev::new(data_ref, self.endian)
        } else {
            return Err(Error::MissingRequiredSection(".debug_abbrev.dwo"));
        };

        // Create offset adjustor functions, see comment on `create_contribution_adjustor` for
        // explanation.
        let adjustor_for_index =
            |id| create_contribution_adjustor(cu_index.as_ref(), tu_index.as_ref(), id);
        let mut abbrev_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugAbbrev);
        let mut line_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugLine);
        let mut loc_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugLoc);
        let mut loclists_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugLocLists);
        let mut rnglists_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugRngLists);
        let mut str_offsets_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugStrOffsets);
        let mut macinfo_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugMacinfo);
        let mut macro_adjustor = adjustor_for_index(gimli::IndexSectionId::DebugMacro);

        let mut seen_debug_info = false;
        let mut seen_debug_types = false;

        // Pass 1: GC each unit and collect its non-shared contributions. The shared sections are
        // per-input-object (a type unit shares them with its compilation unit), so they are
        // emitted once, after this loop, using every unit's GC result.
        let mut pending: Vec<PendingEntry> = Vec::new();

        for section in input.sections() {
            let data;
            let mut iter = match section.name() {
                Ok(".debug_info.dwo" | ".zdebug_info.dwo")
                    // Report an error if a input DWARF package has multiple `.debug_info`
                    // sections.
                    if seen_debug_info && cu_index.is_some() =>
                {
                    return Err(Error::MultipleDebugInfoSection);
                }
                Ok(".debug_info.dwo" | ".zdebug_info.dwo") => {
                    data = section.compressed_data()?.decompress()?;
                    seen_debug_info = true;
                    let debug_info = gimli::DebugInfo::new(&data, self.endian);
                    let mut prescan = debug_info.units();
                    while let Some(h) =
                        prescan.next().map_err(Error::ParseUnitHeader)?
                    {
                        if matches!(
                            h.type_(),
                            UnitType::SplitType { .. } | UnitType::Type { .. }
                        ) {
                            has_type_units = true;
                            break;
                        }
                    }
                    UnitHeaderIterator::DebugInfo(debug_info.units())
                }
                Ok(".debug_types.dwo" | ".zdebug_types.dwo")
                    // Report an error if a input DWARF package has multiple `.debug_types`
                    // sections.
                    if seen_debug_types && tu_index.is_some() =>
                {
                    return Err(Error::MultipleDebugTypesSection);
                }
                Ok(".debug_types.dwo" | ".zdebug_types.dwo") => {
                    data = section.compressed_data()?.decompress()?;
                    seen_debug_types = true;
                    UnitHeaderIterator::DebugTypes(
                        gimli::DebugTypes::new(&data, self.endian).units(),
                    )
                }
                _ => continue,
            };

            while let Some(header) = iter.next().map_err(Error::ParseUnitHeader)? {
                let id = match dwo_identifier_of_unit(&debug_abbrev_section, &header)? {
                    // Report an error if the unit doesn't have a `DwoId` or `DebugTypeSignature`.
                    None => {
                        return Err(Error::NotSplitUnit);
                    }
                    // Report an error when a duplicate compilation unit is found.
                    Some(id @ DwarfObject::Compilation(dwo_id))
                        if self.contained_units.contains(&id) =>
                    {
                        return Err(Error::DuplicateUnit(dwo_id.0));
                    }
                    // Skip duplicate type units, these happen during proper operation of `thorin`.
                    Some(id @ DwarfObject::Type(type_sig))
                        if self.contained_units.contains(&id) =>
                    {
                        debug!(?type_sig, "skipping duplicate type unit, already seen");
                        continue;
                    }
                    Some(id) => id,
                };

                let size: u64 = header
                    .length_including_self()
                    .try_into()
                    .expect("unit header length larger than u64");

                let data = section
                    .compressed_data_range(
                        sess.session(),
                        header.offset().0.try_into().expect("offset larger than u64"),
                        size,
                    )
                    .map_err(Error::DecompressData)?
                    .ok_or(Error::EmptyUnit(id.index()))?;

                let gc_result = sess.run_unit_gc(
                    cu_index.as_ref(),
                    id,
                    data,
                    &debug_abbrev_section,
                    self.endian,
                    has_type_units,
                )?;

                // Use the rewritten `.debug_info` bytes if GC removed any DIEs.
                let debug_info_data = match gc_result.as_ref().and_then(|gc| gc.rewritten.as_ref())
                {
                    Some(rewritten) => rewritten.slice(),
                    None => data,
                };

                let (debug_info, debug_types) = match (&iter, id) {
                    (UnitHeaderIterator::DebugTypes(_), DwarfObject::Type(_)) => {
                        (None, self.obj.append_to_debug_types(debug_info_data))
                    }
                    (_, DwarfObject::Compilation(_) | DwarfObject::Type(_)) => {
                        (self.obj.append_to_debug_info(debug_info_data), None)
                    }
                };

                // Non-shared sections are adjusted here, in unit order. The shared sections
                // (loc, loclists, rnglists, str_offsets) are handled after this loop.
                let debug_abbrev = abbrev_adjustor(id, debug_abbrev)?;
                let debug_line = line_adjustor(id, debug_line)?;
                let debug_macinfo = macinfo_adjustor(id, debug_macinfo)?;
                let debug_macro = macro_adjustor(id, debug_macro)?;

                pending.push(PendingEntry {
                    entry: IndexEntry {
                        encoding,
                        id,
                        debug_info,
                        debug_types,
                        debug_abbrev,
                        debug_line,
                        debug_loc: None,
                        debug_loclists: None,
                        debug_rnglists: None,
                        debug_str_offsets: None,
                        debug_macinfo,
                        debug_macro,
                    },
                    gc_result,
                });
                self.contained_units.insert(id);
            }
        }

        if !seen_debug_info {
            // Report an error if no `.debug_info` section was found.
            return Err(Error::MissingRequiredSection(".debug_info.dwo"));
        }

        // Emit the shared sections once. When list pruning is possible (no type units), this
        // writes recomputed per-unit contributions directly into each `pending` entry and returns
        // `true`; otherwise the shared fields are left as `None` and adjustors fill them below.
        let shared_populated = sess.emit_gc_shared_sections(
            cu_index.as_ref(),
            &mut pending,
            encoding,
            self.endian,
            has_type_units,
            debug_macro.is_some(),
            &mut self.obj,
            &mut self.string_table,
            &mut debug_loc,
            &mut debug_loclists,
            &mut debug_rnglists,
            &mut debug_str_offsets,
        )?;

        // Pass 2: build each unit's index entry. The non-shared fields were filled in pass 1.
        // Fill the four shared fields either from the pending entry (GC path) or from adjustors.
        for unit in &mut pending {
            let id = unit.entry.id;
            if !shared_populated {
                unit.entry.debug_loc = loc_adjustor(id, debug_loc)?;
                unit.entry.debug_loclists = loclists_adjustor(id, debug_loclists)?;
                unit.entry.debug_rnglists = rnglists_adjustor(id, debug_rnglists)?;
                unit.entry.debug_str_offsets = str_offsets_adjustor(id, debug_str_offsets)?;
            }
            let entry = unit.entry;
            debug!(?entry);

            match id {
                DwarfObject::Compilation(_) => self.cu_index_entries.push(entry),
                DwarfObject::Type(_) => self.tu_index_entries.push(entry),
            }
        }

        Ok(())
    }

    /// Return the DWARF package object being created, writing any final sections.
    pub(crate) fn finish(self) -> Result<WritableObject<'file>> {
        let Self { mut obj, string_table, cu_index_entries, tu_index_entries, .. } = self;

        // Write `.debug_str` to the object.
        let _ = obj.append_to_debug_str(&string_table.finish());

        // Write `.debug_{cu,tu}_index` sections to the object.
        debug!("writing cu index");
        let cu_index_data = write_index(self.endian, &cu_index_entries)?;
        let _ = obj.append_to_debug_cu_index(cu_index_data.slice());
        debug!("writing tu index");
        let tu_index_data = write_index(self.endian, &tu_index_entries)?;
        let _ = obj.append_to_debug_tu_index(tu_index_data.slice());

        Ok(obj.finish())
    }
}

impl<'file> fmt::Debug for InProgressDwarfPackage<'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InProgressDwarfPackage")
    }
}
