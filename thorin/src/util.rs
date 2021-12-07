use gimli::{EndianSlice, RunTimeEndian, UnitIndex, UnitType};
use object::{
    write::{Object as WritableObject, SectionId},
    Endianness, Object, ObjectSection, SectionKind,
};
use std::{
    borrow::Cow,
    collections::HashSet,
    path::{Path, PathBuf},
};
use tracing::debug;

use crate::{
    error::{DwpError, Result},
    index::{Bucketable, Contribution, ContributionOffset},
    marker::HasGimliId,
    package::{DwarfObjectIdentifier, PackageFormat},
    relocate::{add_relocations, DwpReader, Relocate, RelocationMap},
    Session,
};

/// Helper function to return the name of a section in a dwarf object.
///
/// Unnecessary but works around a bug in Gimli.
pub(crate) fn dwo_name(id: gimli::SectionId) -> &'static str {
    match id {
        // TODO: patch gimli to return this
        gimli::SectionId::DebugMacinfo => ".debug_macinfo.dwo",
        _ => id.dwo_name().unwrap(),
    }
}

/// Returns the gimli `RunTimeEndian` corresponding to a object `Endianness`.
pub(crate) fn runtime_endian_from_endianness(endianness: Endianness) -> RunTimeEndian {
    match endianness {
        Endianness::Little => RunTimeEndian::Little,
        Endianness::Big => RunTimeEndian::Big,
    }
}

/// Wrapper around `Option<SectionId>` for creating the `SectionId` on first access (if it does
/// not exist).
#[derive(Default)]
pub(crate) struct LazySectionId<Id: HasGimliId> {
    id: Option<SectionId>,
    _id: std::marker::PhantomData<Id>,
}

impl<Id: HasGimliId> LazySectionId<Id> {
    /// Return the `SectionId` for the current section, creating it if it does not exist.
    ///
    /// Don't call this function if the returned id isn't going to be used, otherwise an empty
    /// section would be created.
    pub(crate) fn get<'file>(&mut self, obj: &mut WritableObject<'file>) -> SectionId {
        match self.id {
            Some(id) => id,
            None => {
                let id = obj.add_section(
                    Vec::new(),
                    dwo_name(Id::gimli_id()).as_bytes().to_vec(),
                    SectionKind::Debug,
                );
                self.id = Some(id);
                id
            }
        }
    }
}

/// Helper trait to add `compressed_data_range` function to `ObjectSection` types.
pub(crate) trait CompressedDataRangeExt<'input, 'session: 'input>:
    ObjectSection<'input>
{
    /// Return the decompressed contents of the section data in the given range.
    fn compressed_data_range(
        &self,
        sess: &'session impl Session<RelocationMap>,
        address: u64,
        size: u64,
    ) -> object::Result<Option<&'input [u8]>>;
}

impl<'input, 'session: 'input, S> CompressedDataRangeExt<'input, 'session> for S
where
    S: ObjectSection<'input>,
{
    fn compressed_data_range(
        &self,
        sess: &'session impl Session<RelocationMap>,
        address: u64,
        size: u64,
    ) -> object::Result<Option<&'input [u8]>> {
        let data = self.compressed_data()?.decompress()?;

        /// Originally from `object::read::util`, used in `ObjectSection::data_range`, but not
        /// public.
        fn data_range(
            data: &[u8],
            data_address: u64,
            range_address: u64,
            size: u64,
        ) -> Option<&[u8]> {
            let offset = range_address.checked_sub(data_address)?;
            data.get(offset.try_into().ok()?..)?.get(..size.try_into().ok()?)
        }

        let data_ref = sess.alloc_owned_cow(data);
        Ok(data_range(data_ref, self.address(), address, size))
    }
}

/// Helper trait that abstracts over `gimli::DebugCuIndex` and `gimli::DebugTuIndex`.
pub(crate) trait IndexSection<'input, Endian: gimli::Endianity, R: gimli::Reader>:
    gimli::Section<R>
{
    fn new(section: &'input [u8], endian: Endian) -> Self;

    fn index(self) -> gimli::read::Result<UnitIndex<R>>;
}

impl<'input, Endian: gimli::Endianity> IndexSection<'input, Endian, EndianSlice<'input, Endian>>
    for gimli::DebugCuIndex<EndianSlice<'input, Endian>>
{
    fn new(section: &'input [u8], endian: Endian) -> Self {
        Self::new(section, endian)
    }

    fn index(self) -> gimli::read::Result<UnitIndex<EndianSlice<'input, Endian>>> {
        Self::index(self)
    }
}

impl<'input, Endian: gimli::Endianity> IndexSection<'input, Endian, EndianSlice<'input, Endian>>
    for gimli::DebugTuIndex<EndianSlice<'input, Endian>>
{
    fn new(section: &'input [u8], endian: Endian) -> Self {
        Self::new(section, endian)
    }

    fn index(self) -> gimli::read::Result<UnitIndex<EndianSlice<'input, Endian>>> {
        Self::index(self)
    }
}

/// Returns the parsed unit index from a `.debug_{cu,tu}_index` section.
pub(crate) fn maybe_load_index_section<'input, 'session: 'input, Endian, Index, R, Sess>(
    sess: &'session Sess,
    endian: Endian,
    input: &object::File<'input>,
) -> Result<Option<UnitIndex<R>>>
where
    Endian: gimli::Endianity,
    Index: IndexSection<'input, Endian, R>,
    R: gimli::Reader,
    Sess: Session<RelocationMap>,
{
    // UNWRAP: `Index` types provided known to have `dwo_name` value.
    let index_name = Index::id().dwo_name().unwrap();
    if let Some(index_section) = input.section_by_name(index_name) {
        let index_data = index_section
            .compressed_data()
            .and_then(|d| d.decompress())
            .map_err(DwpError::DecompressData)?;
        let index_data_ref = sess.alloc_owned_cow(index_data);
        let unit_index =
            Index::new(index_data_ref, endian).index().map_err(DwpError::ParseIndex)?;
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
pub(crate) fn create_contribution_adjustor<'input, Identifier, Target, R: 'input>(
    index: Option<&'input UnitIndex<R>>,
) -> Box<dyn FnMut(Identifier, Option<Contribution>) -> Result<Option<Contribution>> + 'input>
where
    Identifier: Bucketable,
    Target: HasGimliId,
    R: gimli::Reader,
{
    let mut adjustment = 0;
    let target_gimli_id = Target::gimli_id();

    Box::new(
        move |identifier: Identifier,
              contribution: Option<Contribution>|
              -> Result<Option<Contribution>> {
            match (&index, contribution) {
                // dwp input with section
                (Some(index), Some(contribution)) => {
                    let identifier = identifier.index();
                    let row_id =
                        index.find(identifier).ok_or(DwpError::UnitNotInIndex(identifier))?;
                    let section = index
                        .sections(row_id)
                        .map_err(|e| DwpError::RowNotInIndex(e, row_id))?
                        .find(|index_section| index_section.section == target_gimli_id)
                        .ok_or(DwpError::SectionNotInRow)?;
                    let adjusted_offset: u64 = contribution.offset.0 + adjustment;
                    adjustment += section.size as u64;

                    Ok(Some(Contribution {
                        offset: ContributionOffset(adjusted_offset),
                        size: section.size as u64,
                    }))
                }
                // dwp input without section
                (Some(_), None) => Ok(None),
                // dwo input with section
                (None, Some(contribution)) => Ok(Some(contribution)),
                // dwo input without section
                (None, None) => Ok(None),
            }
        },
    )
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
#[tracing::instrument(level = "trace", skip(unit))]
pub(crate) fn dwo_identifier_of_unit<R: gimli::Reader>(
    unit: &gimli::Unit<R>,
) -> Option<DwarfObjectIdentifier> {
    match unit.header.type_() {
        // Compilation units with DWARF 5
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => {
            Some(DwarfObjectIdentifier::Compilation(dwo_id.into()))
        }
        // Compilation units with GNU Extension
        UnitType::Compilation => {
            unit.dwo_id.map(|id| DwarfObjectIdentifier::Compilation(id.into()))
        }
        // Type units with DWARF 5
        UnitType::SplitType { type_signature, .. } => {
            Some(DwarfObjectIdentifier::Type(type_signature.into()))
        }
        // Type units with GNU extension
        UnitType::Type { type_signature, .. } => {
            Some(DwarfObjectIdentifier::Type(type_signature.into()))
        }
        // Wrong compilation unit type.
        _ => None,
    }
}

/// Returns the `TargetDwarfObject` of a compilation/type unit.
///
/// In DWARF 5, skeleton compilation unit will contain a `DW_AT_dwo_name` attribute with the name
/// of the dwarf object file containing the split compilation unit with the `DwoId`. In earlier
/// DWARF versions with GNU extension, `DW_AT_GNU_dwo_name` attribute contains a name.
#[tracing::instrument(level = "trace", skip(dwarf, unit))]
pub(crate) fn dwo_id_and_path_of_unit<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
) -> Result<Option<(DwarfObjectIdentifier, PathBuf)>> {
    let identifier = if let Some(identifier) = dwo_identifier_of_unit(unit) {
        identifier
    } else {
        return Ok(None);
    };

    let dwo_name = {
        let mut cursor = unit.header.entries(&unit.abbreviations);
        cursor.next_dfs()?;
        let root = cursor.current().expect("unit without root debugging information entry");

        let dwo_name = if let Some(val) = root.attr_value(gimli::DW_AT_dwo_name)? {
            // DWARF 5
            val
        } else if let Some(val) = root.attr_value(gimli::DW_AT_GNU_dwo_name)? {
            // GNU Extension
            val
        } else {
            return Err(DwpError::MissingDwoName(identifier.index()));
        };

        dwarf.attr_string(&unit, dwo_name)?.to_string()?.into_owned()
    };

    // Prepend the compilation directory if it exists.
    let mut path = if let Some(comp_dir) = &unit.comp_dir {
        PathBuf::from(comp_dir.to_string()?.into_owned())
    } else {
        PathBuf::new()
    };
    path.push(dwo_name);

    Ok(Some((identifier, path)))
}

/// Load and parse an object file.
#[tracing::instrument(level = "trace", skip(sess))]
pub(crate) fn load_object_file<'input, 'session: 'input>(
    sess: &'session impl Session<RelocationMap>,
    path: &'input Path,
) -> Result<object::File<'session>> {
    let data = sess.read_input(path).map_err(DwpError::ReadInput)?;
    object::File::parse(data).map_err(|e| DwpError::ParseObjectFile(e, path.display().to_string()))
}

/// Loads a section of a file from `object::File` into a `gimli::EndianSlice`. Expected to be
/// curried using a closure and provided to `Dwarf::load`.
#[tracing::instrument(level = "trace", skip(sess, obj))]
pub(crate) fn load_file_section<'input, 'session: 'input>(
    sess: &'session impl Session<RelocationMap>,
    id: gimli::SectionId,
    obj: &object::File<'input>,
    is_dwo: bool,
) -> Result<DwpReader<'input>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo { id.dwo_name() } else { Some(id.name()) };

    let data = match name.and_then(|name| obj.section_by_name(&name)) {
        Some(ref section) => {
            if !is_dwo {
                add_relocations(&mut relocations, obj, section)?;
            }
            section.compressed_data()?.decompress()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };

    let data_ref = sess.alloc_owned_cow(data);
    let reader =
        gimli::EndianSlice::new(data_ref, runtime_endian_from_endianness(obj.endianness()));
    let section = reader;
    let relocations = sess.alloc_relocation(relocations);
    Ok(Relocate { relocations, section, reader })
}

/// Parse the executable, collect split unit identifiers to be found in input DWARF objects and add
/// new input DWARF objects.
#[tracing::instrument(level = "trace", skip(sess, obj))]
pub(crate) fn parse_executable<'input, 'session: 'input>(
    sess: &'session impl Session<RelocationMap>,
    obj: &object::File<'input>,
    target_dwarf_objects: &mut HashSet<DwarfObjectIdentifier>,
    dwarf_object_paths: &mut Vec<PathBuf>,
) -> Result<Option<(PackageFormat, object::Architecture, object::Endianness)>> {
    let mut load_section =
        |id: gimli::SectionId| -> Result<_> { load_file_section(sess, id, &obj, false) };

    let dwarf = gimli::Dwarf::load(&mut load_section)?;

    let format =
        if let Some(root_header) = dwarf.units().next().map_err(DwpError::ParseUnitHeader)? {
            PackageFormat::from_dwarf_version(root_header.version())
        } else {
            return Ok(None);
        };
    debug!(?format);

    let mut iter = dwarf.units();
    while let Some(header) = iter.next().map_err(DwpError::ParseUnitHeader)? {
        let unit = dwarf.unit(header).map_err(DwpError::ParseUnit)?;
        if let Some((target, path)) = dwo_id_and_path_of_unit(&dwarf, &unit)? {
            // Only add `DwoId`s to the target vector, not `DebugTypeSignature`s. There doesn't
            // appear to be a "skeleton type unit" to find the corresponding unit of (there are
            // normal type units in an executable, but should we expect to find a corresponding
            // split type unit for those?).
            if matches!(target, DwarfObjectIdentifier::Compilation(_)) {
                debug!(?target, "adding target");
                target_dwarf_objects.insert(target);
            }

            debug!(?path, "adding path");
            dwarf_object_paths.push(path);
        }
    }

    Ok(Some((format, obj.architecture(), obj.endianness())))
}
