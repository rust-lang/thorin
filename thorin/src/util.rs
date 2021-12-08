use gimli::{EndianSlice, RunTimeEndian, UnitIndex, UnitType};
use object::{
    write::{Object as WritableObject, SectionId},
    Endianness, Object, ObjectSection, SectionKind,
};

use crate::{
    error::{Error, Result},
    index::{Bucketable, Contribution, ContributionOffset},
    marker::HasGimliId,
    package::{DwarfObjectIdentifier, PackageFormat},
    relocate::RelocationMap,
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
    format: PackageFormat,
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
            .map_err(Error::DecompressData)?;
        let index_data_ref = sess.alloc_owned_cow(index_data);
        let unit_index = Index::new(index_data_ref, endian)
            .index()
            .map_err(|e| Error::ParseIndex(e, index_name.to_string()))?;

        if !format.is_compatible_index_version(unit_index.version()) {
            return Err(Error::IncompatibleIndexVersion(
                index_name.to_string(),
                format.to_string(),
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
                    let row_id = index.find(identifier).ok_or(Error::UnitNotInIndex(identifier))?;
                    let section = index
                        .sections(row_id)
                        .map_err(|e| Error::RowNotInIndex(e, row_id))?
                        .find(|index_section| index_section.section == target_gimli_id)
                        .ok_or(Error::SectionNotInRow)?;
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
