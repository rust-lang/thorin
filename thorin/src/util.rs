use gimli::{Encoding, RunTimeEndian, UnitIndex, UnitType};
use object::{Endianness, Object, ObjectSection};

use crate::{
    error::{Error, Result},
    ext::{IndexSectionExt, PackageFormatExt},
    index::{Bucketable, Contribution, ContributionOffset},
    package::DwarfObjectIdentifier,
    relocate::RelocationMap,
    Session,
};

/// Returns the gimli `RunTimeEndian` corresponding to a object `Endianness`.
pub(crate) fn runtime_endian_from_endianness(endianness: Endianness) -> RunTimeEndian {
    match endianness {
        Endianness::Little => RunTimeEndian::Little,
        Endianness::Big => RunTimeEndian::Big,
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
    target_section_id: gimli::SectionId,
) -> Box<
    dyn FnMut(DwarfObjectIdentifier, Option<Contribution>) -> Result<Option<Contribution>> + 'input,
>
where
    R: gimli::Reader,
{
    let mut cu_adjustment = 0;
    let mut tu_adjustment = 0;

    Box::new(
        move |identifier: DwarfObjectIdentifier,
              contribution: Option<Contribution>|
              -> Result<Option<Contribution>> {
            let (adjustment, index) = match identifier {
                DwarfObjectIdentifier::Compilation(_) => (&mut cu_adjustment, &cu_index),
                DwarfObjectIdentifier::Type(_) => (&mut tu_adjustment, &tu_index),
            };
            match (index, contribution) {
                // dwp input with section
                (Some(index), Some(contribution)) => {
                    let idx = identifier.index();
                    let row_id = index.find(idx).ok_or(Error::UnitNotInIndex(idx))?;
                    let section = index
                        .sections(row_id)
                        .map_err(|e| Error::RowNotInIndex(e, row_id))?
                        .find(|index_section| index_section.section == target_section_id)
                        .ok_or(Error::SectionNotInRow)?;
                    let adjusted_offset: u64 = contribution.offset.0 + *adjustment;
                    *adjustment += section.size as u64;

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
#[tracing::instrument(level = "trace", skip(debug_abbrev, header))]
pub(crate) fn dwo_identifier_of_unit<R: gimli::Reader>(
    debug_abbrev: &gimli::DebugAbbrev<R>,
    header: &gimli::UnitHeader<R>,
) -> Result<Option<DwarfObjectIdentifier>> {
    match header.type_() {
        // Compilation units with DWARF 5
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => {
            Ok(Some(DwarfObjectIdentifier::Compilation(dwo_id.into())))
        }
        // Compilation units with GNU Extension
        UnitType::Compilation => {
            let abbreviations =
                header.abbreviations(&debug_abbrev).map_err(Error::ParseUnitAbbreviations)?;
            let mut cursor = header.entries(&abbreviations);
            cursor.next_dfs()?;
            let root = cursor.current().expect("unit without root debugging information entry");
            match root.tag() {
                gimli::DW_TAG_compile_unit | gimli::DW_TAG_type_unit => (),
                _ => return Err(Error::TopLevelDieNotUnit),
            }
            let mut attrs = root.attrs();
            while let Some(attr) = attrs.next().map_err(Error::ParseUnitAttribute)? {
                match (attr.name(), attr.value()) {
                    (gimli::constants::DW_AT_GNU_dwo_id, gimli::AttributeValue::DwoId(dwo_id)) => {
                        return Ok(Some(DwarfObjectIdentifier::Compilation(dwo_id.into())))
                    }
                    _ => (),
                }
            }

            Ok(None)
        }
        // Type units with DWARF 5
        UnitType::SplitType { type_signature, .. } => {
            Ok(Some(DwarfObjectIdentifier::Type(type_signature.into())))
        }
        // Type units with GNU extension
        UnitType::Type { type_signature, .. } => {
            Ok(Some(DwarfObjectIdentifier::Type(type_signature.into())))
        }
        // Wrong compilation unit type.
        _ => Ok(None),
    }
}
