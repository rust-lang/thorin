use anyhow::{anyhow, Context, Result};
use gimli::{
    write::EndianVec, write::Writer, DebugStrOffsetsBase, DebugStrOffsetsIndex, DwarfFileType,
    Encoding, Format, Reader, RunTimeEndian, UnitType,
};
use object::{
    write::{Object as WritableObject, SectionId},
    BinaryFormat, Object, ObjectSection,
};
use std::{collections::HashSet, fmt};
use tracing::{debug, trace, warn};
use typed_arena::Arena;

use crate::{
    error::DwpError,
    index::{
        Bucketable, Contribution, ContributionOffset, CuIndexEntry, IndexCollection, TuIndexEntry,
    },
    marker::{
        DebugAbbrev, DebugCuIndex, DebugInfo, DebugLine, DebugLoc, DebugLocLists, DebugMacinfo,
        DebugMacro, DebugRngLists, DebugStr, DebugStrOffsets, DebugTuIndex, DebugTypes,
    },
    relocate::DwpReader,
    strings::DwpStringTable,
    util::{
        create_contribution_adjustor, dwo_identifier_of_unit, dwo_name, maybe_load_index_section,
        runtime_endian_from_endianness, CompressedDataRangeExt, LazySectionId,
    },
};

/// DWARF packages come in pre-standard GNU extension format or DWARF 5 standardized format.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PackageFormat {
    /// GNU's DWARF package file format (preceded standardized version from DWARF 5).
    ///
    /// See [specification](https://gcc.gnu.org/wiki/DebugFissionDWP).
    GnuExtension,
    /// DWARF 5-standardized package file format.
    ///
    /// See Sec 7.3.5 and Appendix F of [DWARF specification](https://dwarfstd.org/doc/DWARF5.pdf).
    DwarfStd,
}

impl PackageFormat {
    /// Returns the appropriate `PackageFormat` for the given version of DWARF being used.
    pub(crate) fn from_dwarf_version(version: u16) -> Self {
        if version >= 5 {
            PackageFormat::DwarfStd
        } else {
            PackageFormat::GnuExtension
        }
    }
}

impl fmt::Display for PackageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PackageFormat::GnuExtension => write!(f, "GNU Extension"),
            PackageFormat::DwarfStd => write!(f, "Dwarf Standard"),
        }
    }
}

impl Default for PackageFormat {
    fn default() -> Self {
        PackageFormat::GnuExtension
    }
}

/// New-type'd index (constructed from `gimli::DwoId`) with a custom `Debug` implementation to
/// print in hexadecimal.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct DwoId(pub(crate) u64);

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
pub(crate) enum DwarfObjectIdentifier {
    /// `DwoId` identifying compilation units.
    Compilation(DwoId),
    /// `DebugTypeSignature` identifying type units.
    Type(DebugTypeSignature),
}

impl Bucketable for DwarfObjectIdentifier {
    fn index(&self) -> u64 {
        match *self {
            DwarfObjectIdentifier::Compilation(dwo_id) => dwo_id.index(),
            DwarfObjectIdentifier::Type(type_signature) => type_signature.index(),
        }
    }
}

/// In-progress DWARF package being produced.
pub(crate) struct OutputPackage<'file, Endian: gimli::Endianity> {
    /// Object file being created.
    obj: WritableObject<'file>,

    /// Format of the DWARF package being created.
    format: PackageFormat,
    /// Endianness of the DWARF package being created.
    endian: Endian,

    /// Identifier for the `.debug_cu_index.dwo` section in the object file being created. Format
    /// depends on whether this is a GNU extension-flavoured package or DWARF 5-flavoured package.
    debug_cu_index: LazySectionId<DebugCuIndex>,
    /// Identifier for the `.debug_tu_index.dwo` section in the object file being created. Format
    /// depends on whether this is a GNU extension-flavoured package or DWARF 5-flavoured package.
    debug_tu_index: LazySectionId<DebugTuIndex>,

    /// Identifier for the `.debug_info.dwo` section in the object file being created.
    ///
    /// Contains concatenated compilation units from `.debug_info.dwo` sections of input DWARF
    /// objects with matching `DW_AT_GNU_dwo_id` attributes.
    debug_info: LazySectionId<DebugInfo>,
    /// Identifier for the `.debug_abbrev.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_abbrev.dwo` sections from input DWARF objects.
    debug_abbrev: LazySectionId<DebugAbbrev>,
    /// Identifier for the `.debug_str.dwo` section in the object file being created.
    ///
    /// Contains a string table merged from the `.debug_str.dwo` sections of input DWARF
    /// objects.
    debug_str: LazySectionId<DebugStr>,
    /// Identifier for the `.debug_types.dwo` section in the object file being created.
    ///
    /// Contains concatenated type units from `.debug_types.dwo` sections of input DWARF
    /// objects with matching type signatures.
    debug_types: LazySectionId<DebugTypes>,
    /// Identifier for the `.debug_line.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_line.dwo` sections from input DWARF objects.
    debug_line: LazySectionId<DebugLine>,
    /// Identifier for the `.debug_loc.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_loc.dwo` sections from input DWARF objects. Only with DWARF
    /// 4 GNU extension.
    debug_loc: LazySectionId<DebugLoc>,
    /// Identifier for the `.debug_loclists.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_loclists.dwo` sections from input DWARF objects. Only with
    /// DWARF 5.
    debug_loclists: LazySectionId<DebugLocLists>,
    /// Identifier for the `.debug_rnglists.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_rnglists.dwo` sections from input DWARF objects. Only with
    /// DWARF 5.
    debug_rnglists: LazySectionId<DebugRngLists>,
    /// Identifier for the `.debug_str_offsets.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_str_offsets.dwo` sections from input DWARF objects,
    /// re-written with offsets into the merged `.debug_str.dwo` section.
    debug_str_offsets: LazySectionId<DebugStrOffsets>,
    /// Identifier for the `.debug_macinfo.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_macinfo.dwo` sections from input DWARF objects. Only with
    /// DWARF 4 GNU extension.
    debug_macinfo: LazySectionId<DebugMacinfo>,
    /// Identifier for the `.debug_macro.dwo` section in the object file being created.
    ///
    /// Contains concatenated `.debug_macro.dwo` sections from input DWARF objects.
    debug_macro: LazySectionId<DebugMacro>,

    /// Compilation unit index entries (offsets + sizes) being accumulated.
    cu_index_entries: Vec<CuIndexEntry>,
    /// Type unit index entries (offsets + sizes) being accumulated.
    tu_index_entries: Vec<TuIndexEntry>,

    /// In-progress string table being accumulated. Used to write final `.debug_str.dwo` and
    /// `.debug_str_offsets.dwo` for each DWARF object.
    string_table: DwpStringTable<Endian>,

    /// `DebugTypeSignature`s of type units and `DwoId`s of compilation units that have already
    /// been added to the output package.
    ///
    /// Used when adding new TU index entries to de-duplicate type units (as required by the
    /// specification). Also used to check that all dwarf objects referenced by executables
    /// have been found.
    seen_units: HashSet<DwarfObjectIdentifier>,
}

impl<'file, Endian: gimli::Endianity> OutputPackage<'file, Endian> {
    /// Create an object file with empty sections that will be later populated from DWARF object
    /// files.
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(
        format: PackageFormat,
        architecture: object::Architecture,
        endianness: object::Endianness,
    ) -> OutputPackage<'file, RunTimeEndian> {
        let obj = WritableObject::new(BinaryFormat::Elf, architecture, endianness);

        let endian = runtime_endian_from_endianness(endianness);
        let string_table = DwpStringTable::new(endian);

        OutputPackage {
            obj,
            format,
            endian,
            string_table,
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
            cu_index_entries: Default::default(),
            tu_index_entries: Default::default(),
            seen_units: Default::default(),
        }
    }

    /// Return the `SectionId` corresponding to a `gimli::SectionId`, creating a id if it hasn't
    /// been created before.
    ///
    /// Don't call this function if the returned id isn't going to be used, otherwise an empty
    /// section would be created.
    fn section(&mut self, id: gimli::SectionId) -> SectionId {
        use gimli::SectionId::*;
        match id {
            DebugCuIndex => self.debug_cu_index.get(&mut self.obj),
            DebugTuIndex => self.debug_tu_index.get(&mut self.obj),
            DebugInfo => self.debug_info.get(&mut self.obj),
            DebugAbbrev => self.debug_abbrev.get(&mut self.obj),
            DebugStr => self.debug_str.get(&mut self.obj),
            DebugTypes => self.debug_types.get(&mut self.obj),
            DebugLine => self.debug_line.get(&mut self.obj),
            DebugLoc => self.debug_loc.get(&mut self.obj),
            DebugLocLists => self.debug_loclists.get(&mut self.obj),
            DebugRngLists => self.debug_rnglists.get(&mut self.obj),
            DebugStrOffsets => self.debug_str_offsets.get(&mut self.obj),
            DebugMacinfo => self.debug_macinfo.get(&mut self.obj),
            DebugMacro => self.debug_macro.get(&mut self.obj),
            _ => panic!("section invalid in dwarf package"),
        }
    }

    /// Append the contents of a section from the input DWARF object to the equivalent section in
    /// the output object, with no further processing.
    #[tracing::instrument(level = "trace", skip(input))]
    fn append_section<'input, 'output>(
        &mut self,
        input: &object::File<'input>,
        input_id: gimli::SectionId,
        required: bool,
    ) -> Result<Option<Contribution>> {
        let name = dwo_name(input_id);
        match input.section_by_name(name) {
            Some(section) => {
                let size = section.size();
                let data = section.compressed_data()?.decompress()?;
                if !data.is_empty() {
                    let id = self.section(input_id);
                    let offset = self.obj.append_section_data(id, &data, section.align());
                    Ok(Some(Contribution { offset: ContributionOffset(offset), size }))
                } else {
                    Ok(None)
                }
            }
            None if required => Err(anyhow!(DwpError::MissingRequiredSection(name.to_string()))),
            None => {
                trace!("section doesn't exist");
                Ok(None)
            }
        }
    }

    /// Read the string offsets from `.debug_str_offsets.dwo` in the DWARF object, adding each to
    /// the in-progress `.debug_str` (`DwpStringTable`) and building a new `.debug_str_offsets.dwo`
    /// to be the current DWARF object's contribution to the DWARF package.
    #[tracing::instrument(level = "trace", skip(arena_compression, input, input_dwarf))]
    fn append_str_offsets<'input, 'output, 'arena: 'input>(
        &mut self,
        arena_compression: &'arena Arena<Vec<u8>>,
        input: &object::File<'input>,
        input_dwarf: &gimli::Dwarf<DwpReader<'arena>>,
        encoding: Encoding,
        format: PackageFormat,
    ) -> Result<Option<Contribution>> {
        // UNWRAP: `dwo_name` has known return value for this section.
        let section_name = gimli::SectionId::DebugStrOffsets.dwo_name().unwrap();
        let section = match input.section_by_name(section_name) {
            Some(section) => section,
            // `.debug_str_offsets.dwo` is an optional section.
            None => return Ok(None),
        };
        let section_size = section.size();

        let mut data = EndianVec::new(self.endian);

        // `DebugStrOffsetsBase` knows to skip past the header with DWARF 5.
        let base: gimli::DebugStrOffsetsBase<usize> =
            DebugStrOffsetsBase::default_for_encoding_and_file(encoding, DwarfFileType::Dwo);

        // Copy the DWARF 5 header exactly.
        if format == PackageFormat::DwarfStd {
            // `DebugStrOffsetsBase` should start from after DWARF 5's header, check that.
            assert!(base.0 != 0);
            let size = base.0.try_into().expect("base offset is larger than a u64");
            let header_data = section
                .compressed_data_range(arena_compression, 0, size)?
                .ok_or(DwpError::StrOffsetsMissingHeader)?;
            data.write(&header_data)?;
        }

        let entry_size = match encoding.format {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 8,
        };

        let num_elements = section_size / entry_size;
        debug!(?section_size, ?num_elements);

        for i in 0..num_elements {
            let dwo_index = DebugStrOffsetsIndex(i as usize);
            let dwo_offset = input_dwarf
                .debug_str_offsets
                .get_str_offset(encoding.format, base, dwo_index)
                .context(DwpError::OffsetAtIndex(i))?;
            let dwo_str = input_dwarf
                .debug_str
                .get_str(dwo_offset)
                .context(DwpError::StrAtOffset(dwo_offset.0))?;
            let dwo_str = dwo_str.to_string()?;

            let dwp_offset = self
                .string_table
                .get_or_insert(dwo_str.as_ref())
                .context(DwpError::WritingStrToStringTable)?;
            debug!(?i, ?dwo_str, "dwo_offset={:#x} dwp_offset={:#x}", dwo_offset.0, dwp_offset.0);

            match encoding.format {
                Format::Dwarf32 => {
                    let dwp_offset =
                        dwp_offset.0.try_into().expect("string offset too large for u32");
                    data.write_u32(dwp_offset)?;
                }
                Format::Dwarf64 => {
                    let dwp_offset =
                        dwp_offset.0.try_into().expect("string offset too large for u64");
                    data.write_u64(dwp_offset)?;
                }
            }
        }

        if num_elements > 0 {
            let id = self.debug_str_offsets.get(&mut self.obj);
            let offset = self.obj.append_section_data(id, data.slice(), section.align());
            Ok(Some(Contribution {
                offset: ContributionOffset(offset),
                size: section_size.try_into().expect("section size too large for u32"),
            }))
        } else {
            Ok(None)
        }
    }

    /// Append a unit from the input DWARF object to the `.debug_info` (or `.debug_types`) section
    /// in the output object. Only appends unit if it has a `DwarfObjectIdentifier` matching the
    /// target `DwarfObjectIdentifier`.
    #[tracing::instrument(
        level = "trace",
        skip(arena_compression, section, unit, append_cu_contribution, append_tu_contribution)
    )]
    fn append_unit<'input, 'arena: 'input, 'output: 'arena, CuOp, Sect, TuOp>(
        &mut self,
        arena_compression: &'arena Arena<Vec<u8>>,
        section: &Sect,
        unit: &gimli::Unit<DwpReader<'arena>>,
        mut append_cu_contribution: CuOp,
        mut append_tu_contribution: TuOp,
    ) -> Result<()>
    where
        CuOp: FnMut(&mut Self, DwoId, Contribution) -> Result<()>,
        TuOp: FnMut(&mut Self, DebugTypeSignature, Contribution) -> Result<()>,
        Sect: CompressedDataRangeExt<'input, 'arena>,
    {
        let size: u64 = unit
            .header
            .length_including_self()
            .try_into()
            .expect("unit header lenghh bigger than u64");
        let offset = unit.header.offset();

        let identifier = dwo_identifier_of_unit(&unit);
        match (unit.header.type_(), identifier) {
            (
                UnitType::Compilation | UnitType::SplitCompilation(..),
                Some(DwarfObjectIdentifier::Compilation(dwo_id)),
            ) => {
                debug!(?dwo_id, "compilation unit");
                if self.seen_units.contains(&DwarfObjectIdentifier::Compilation(dwo_id)) {
                    // Return early if a unit with this type signature has already been seen.
                    warn!("skipping {:?}, already seen", dwo_id);
                    return Ok(());
                }

                let offset = offset
                    .as_debug_info_offset()
                    .expect("offset from `.debug_info.dwo` section is not a `DebugInfoOffset`")
                    .0;
                let data = section
                    .compressed_data_range(arena_compression, offset.try_into().unwrap(), size)?
                    .ok_or(DwpError::EmptyUnit(dwo_id.0))?;

                if !data.is_empty() {
                    let id = self.debug_info.get(&mut self.obj);
                    let offset = self.obj.append_section_data(id, data, section.align());
                    let contribution = Contribution { offset: ContributionOffset(offset), size };
                    append_cu_contribution(self, dwo_id, contribution)?;
                    self.seen_units.insert(DwarfObjectIdentifier::Compilation(dwo_id));
                }

                Ok(())
            }
            (
                UnitType::Type { .. } | UnitType::SplitType { .. },
                Some(DwarfObjectIdentifier::Type(type_signature)),
            ) => {
                debug!(?type_signature, "type unit");
                if self.seen_units.contains(&DwarfObjectIdentifier::Type(type_signature)) {
                    // Return early if a unit with this type signature has already been seen.
                    warn!("skipping {:?}, already seen", type_signature);
                    return Ok(());
                }

                let offset = match self.format {
                    PackageFormat::GnuExtension => offset
                        .as_debug_types_offset()
                        .expect(
                            "offset from `.debug_types.dwo` section is not a `DebugTypesOffset`",
                        )
                        .0,
                    PackageFormat::DwarfStd => {
                        offset
                            .as_debug_info_offset()
                            .expect(
                                "offset from `.debug_info.dwo` section is not a `DebugInfoOffset`",
                            )
                            .0
                    }
                };
                let data = section
                    .compressed_data_range(arena_compression, offset.try_into().unwrap(), size)?
                    .ok_or(DwpError::EmptyUnit(type_signature.0))?;

                if !data.is_empty() {
                    let id = match self.format {
                        PackageFormat::GnuExtension => self.debug_types.get(&mut self.obj),
                        PackageFormat::DwarfStd => self.debug_info.get(&mut self.obj),
                    };
                    let offset = self.obj.append_section_data(id, data, section.align());
                    let contribution = Contribution { offset: ContributionOffset(offset), size };
                    append_tu_contribution(self, type_signature, contribution)?;
                    self.seen_units.insert(DwarfObjectIdentifier::Type(type_signature));
                }

                Ok(())
            }
            (_, Some(..)) => {
                warn!("unit in dwarf object is not a split unit, skipping");
                Ok(())
            }
            (_, None) => Ok(()),
        }
    }

    /// Process a DWARF object. Copies relevant sections, compilation/type units and strings from
    /// DWARF object into output object.
    #[tracing::instrument(level = "trace", skip(arena_compression, input, input_dwarf))]
    pub(crate) fn append_dwarf_object<'input, 'output, 'arena: 'input>(
        &mut self,
        arena_compression: &'arena Arena<Vec<u8>>,
        input: &object::File<'input>,
        input_dwarf: &gimli::Dwarf<DwpReader<'arena>>,
        encoding: Encoding,
        format: PackageFormat,
    ) -> Result<()> {
        use gimli::SectionId::*;

        // Concatenate contents of sections from the DWARF object into the corresponding section in
        // the output.
        let debug_abbrev = self
            .append_section(&input, DebugAbbrev, true)
            .context(DwpError::ConcatenatingSection(".debug_abbrev.dwo"))?
            .expect("required section didn't return error");
        let debug_line = self
            .append_section(&input, DebugLine, false)
            .context(DwpError::ConcatenatingSection(".debug_line.dwo"))?;
        let debug_macro = self
            .append_section(&input, DebugMacro, false)
            .context(DwpError::ConcatenatingSection(".debug_macro.dwo"))?;

        let (debug_loc, debug_macinfo, debug_loclists, debug_rnglists) = match self.format {
            PackageFormat::GnuExtension => {
                // Only `.debug_loc.dwo` and `.debug_macinfo.dwo` with the GNU extension.
                let debug_loc = self
                    .append_section(&input, DebugLoc, false)
                    .context(DwpError::ConcatenatingSection(".debug_loc.dwo"))?;
                let debug_macinfo = self
                    .append_section(&input, DebugMacinfo, false)
                    .context(DwpError::ConcatenatingSection(".debug_macinfo.dwo"))?;
                (debug_loc, debug_macinfo, None, None)
            }
            PackageFormat::DwarfStd => {
                // Only `.debug_loclists.dwo` and `.debug_rnglists.dwo` with DWARF 5.
                let debug_loclists = self
                    .append_section(&input, DebugLocLists, false)
                    .context(DwpError::ConcatenatingSection(".debug_loclists.dwo"))?;
                let debug_rnglists = self
                    .append_section(&input, DebugRngLists, false)
                    .context(DwpError::ConcatenatingSection(".debug_rnglists.dwo"))?;
                (None, None, debug_loclists, debug_rnglists)
            }
        };

        // Concatenate string offsets from the DWARF object into the `.debug_str_offsets` section
        // in the output, rewriting offsets to be based on the new, merged string table.
        let debug_str_offsets = self
            .append_str_offsets(arena_compression, &input, &input_dwarf, encoding, format)
            .context(DwpError::AddingStrOffsets)?;

        // Load index sections (if they exist).
        let cu_index = maybe_load_index_section::<_, gimli::DebugCuIndex<_>, _>(
            arena_compression,
            self.endian,
            input,
        )
        .context(DwpError::LoadCuIndex)?;
        let tu_index = maybe_load_index_section::<_, gimli::DebugTuIndex<_>, _>(
            arena_compression,
            self.endian,
            input,
        )
        .context(DwpError::LoadTuIndex)?;

        // Create offset adjustor functions, see comment on `create_contribution_adjustor` for
        // explanation.
        let mut abbrev_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugAbbrev, _>(cu_index.as_ref());
        let mut line_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugLine, _>(cu_index.as_ref());
        let mut loc_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugLoc, _>(cu_index.as_ref());
        let mut loclists_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugLocLists, _>(cu_index.as_ref());
        let mut rnglists_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugRngLists, _>(cu_index.as_ref());
        let mut str_offsets_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugStrOffsets, _>(cu_index.as_ref());
        let mut macinfo_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugMacinfo, _>(cu_index.as_ref());
        let mut macro_cu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugMacro, _>(cu_index.as_ref());

        let mut abbrev_tu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugAbbrev, _>(tu_index.as_ref());
        let mut line_tu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugLine, _>(tu_index.as_ref());
        let mut str_offsets_tu_adjustor =
            create_contribution_adjustor::<_, crate::marker::DebugStrOffsets, _>(tu_index.as_ref());

        // UNWRAP: `dwo_name` has known return value for this section.
        let debug_info_name = gimli::SectionId::DebugInfo.dwo_name().unwrap();
        let debug_info_section = input
            .section_by_name(debug_info_name)
            .with_context(|| DwpError::MissingRequiredSection(debug_info_name.to_string()))?;

        // Append compilation (and type units, in DWARF 5) from `.debug_info`.
        let mut iter = input_dwarf.units();
        while let Some(header) = iter.next().context(DwpError::ParseUnitHeader)? {
            let unit = input_dwarf.unit(header).context(DwpError::ParseUnit)?;
            self.append_unit(
                arena_compression,
                &debug_info_section,
                &unit,
                |this, dwo_id, debug_info| {
                    let debug_abbrev = abbrev_cu_adjustor(dwo_id, Some(debug_abbrev))
                        .context(DwpError::AdjustingContribution(".debug_abbrev.dwo"))?
                        .expect("mandatory section cannot be adjusted");
                    let debug_line = line_cu_adjustor(dwo_id, debug_line)
                        .context(DwpError::AdjustingContribution(".debug_line.dwo"))?;
                    let debug_loc = loc_cu_adjustor(dwo_id, debug_loc)
                        .context(DwpError::AdjustingContribution(".debug_loc.dwo"))?;
                    let debug_loclists = loclists_cu_adjustor(dwo_id, debug_loclists)
                        .context(DwpError::AdjustingContribution(".debug_loclists.dwo"))?;
                    let debug_rnglists = rnglists_cu_adjustor(dwo_id, debug_rnglists)
                        .context(DwpError::AdjustingContribution(".debug_rnglists.dwo"))?;
                    let debug_str_offsets = str_offsets_cu_adjustor(dwo_id, debug_str_offsets)
                        .context(DwpError::AdjustingContribution(".debug_str_offsets.dwo"))?;
                    let debug_macinfo = macinfo_cu_adjustor(dwo_id, debug_macinfo)
                        .context(DwpError::AdjustingContribution(".debug_macinfo.dwo"))?;
                    let debug_macro = macro_cu_adjustor(dwo_id, debug_macro)
                        .context(DwpError::AdjustingContribution(".debug_macro.dwo"))?;

                    this.cu_index_entries.push(CuIndexEntry {
                        dwo_id,
                        debug_info,
                        debug_abbrev,
                        debug_line,
                        debug_loc,
                        debug_loclists,
                        debug_rnglists,
                        debug_str_offsets,
                        debug_macinfo,
                        debug_macro,
                    });
                    Ok(())
                },
                |this, type_sig, debug_info| {
                    let debug_abbrev = abbrev_tu_adjustor(type_sig, Some(debug_abbrev))
                        .context(DwpError::AdjustingContribution(".debug_abbrev.dwo"))?
                        .expect("mandatory section cannot be adjusted");
                    let debug_line = line_tu_adjustor(type_sig, debug_line)
                        .context(DwpError::AdjustingContribution(".debug_line.dwo"))?;
                    let debug_str_offsets = str_offsets_tu_adjustor(type_sig, debug_str_offsets)
                        .context(DwpError::AdjustingContribution(".debug_str_offsets.dwo"))?;

                    this.tu_index_entries.push(TuIndexEntry {
                        type_signature: type_sig,
                        debug_info_or_types: debug_info,
                        debug_abbrev,
                        debug_line,
                        debug_str_offsets,
                    });
                    Ok(())
                },
            )
            .context(DwpError::AddingUnitsFromSection(".debug_info.dwo"))?;
        }

        // Append type units from `.debug_info` with the GNU extension.
        if self.format == PackageFormat::GnuExtension {
            // UNWRAP: `dwo_name` has known return value for this section.
            let debug_types_name = gimli::SectionId::DebugTypes.dwo_name().unwrap();
            if let Some(debug_types_section) = input.section_by_name(debug_types_name) {
                let mut iter = input_dwarf.type_units();
                while let Some(header) = iter.next().context(DwpError::ParseUnitHeader)? {
                    let unit = input_dwarf.unit(header).context(DwpError::ParseUnit)?;
                    self.append_unit(
                        arena_compression,
                        &debug_types_section,
                        &unit,
                        |_, _, _| {
                            /* no-op, no compilation units in `.debug_types` */
                            Ok(())
                        },
                        |this, type_sig, debug_info_or_types| {
                            let debug_abbrev = abbrev_tu_adjustor(type_sig, Some(debug_abbrev))
                                .context(DwpError::AdjustingContribution(".debug_abbrev.dwo"))?
                                .expect("mandatory section cannot be adjusted");
                            let debug_line = line_tu_adjustor(type_sig, debug_line)
                                .context(DwpError::AdjustingContribution(".debug_line.dwo"))?;
                            let debug_str_offsets =
                                str_offsets_tu_adjustor(type_sig, debug_str_offsets).context(
                                    DwpError::AdjustingContribution(".debug_str_offsets.dwo"),
                                )?;

                            this.tu_index_entries.push(TuIndexEntry {
                                type_signature: type_sig,
                                debug_info_or_types,
                                debug_abbrev,
                                debug_line,
                                debug_str_offsets,
                            });
                            Ok(())
                        },
                    )
                    .context(DwpError::AddingUnitsFromSection(".debug_types.dwo"))?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn verify(&self, targets: &HashSet<DwarfObjectIdentifier>) -> Result<()> {
        if targets.difference(&self.seen_units).count() != 0 {
            let missing = targets.difference(&self.seen_units).cloned().collect();
            return Err(anyhow!(DwpError::MissingReferencedUnit(missing)));
        }

        Ok(())
    }

    pub(crate) fn emit(mut self, buffer: &mut dyn object::write::WritableBuffer) -> Result<()> {
        // Write `.debug_str` to the object.
        let _ = self.string_table.write(&mut self.debug_str, &mut self.obj);

        // Write `.debug_{cu,tu}_index` sections to the object.
        debug!("writing cu index");
        self.cu_index_entries
            .write_index(self.endian, self.format, &mut self.obj, &mut self.debug_cu_index)
            .context(DwpError::WriteCuIndex)?;
        debug!("writing tu index");
        self.tu_index_entries
            .write_index(self.endian, self.format, &mut self.obj, &mut self.debug_tu_index)
            .context(DwpError::WriteTuIndex)?;

        // Write the contents of the entire object to the buffer.
        self.obj.emit(buffer).map_err(From::from)
    }
}

impl<'file, Endian: gimli::Endianity> fmt::Debug for OutputPackage<'file, Endian> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputPackage({})", self.format)
    }
}
