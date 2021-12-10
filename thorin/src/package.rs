use std::{collections::HashSet, fmt};

use gimli::{Encoding, RunTimeEndian, UnitType};
use object::{
    write::{Object as WritableObject, SectionId},
    BinaryFormat, Object, ObjectSection, SectionKind,
};
use tracing::{debug, trace};

use crate::{
    error::{Error, Result},
    index::{
        Bucketable, Contribution, ContributionOffset, CuIndexEntry, IndexCollection, TuIndexEntry,
    },
    relocate::{DwpReader, RelocationMap},
    strings::PackageStringTable,
    util::{
        create_contribution_adjustor, dwo_identifier_of_unit, dwo_name, maybe_load_index_section,
        runtime_endian_from_endianness, CompressedDataRangeExt,
    },
    Session,
};

pub(crate) trait PackageFormatExt {
    /// Returns `true` if this `Encoding` would produce to a DWARF 5-standardized package file.
    ///
    /// See Sec 7.3.5 and Appendix F of [DWARF specification](https://dwarfstd.org/doc/DWARF5.pdf).
    fn is_std_dwarf_package_format(&self) -> bool;

    /// Returns `true` if this `Encoding` would produce a GNU Extension DWARF package file
    /// (preceded standardized version from DWARF 5).
    ///
    /// See [specification](https://gcc.gnu.org/wiki/DebugFissionDWP).
    fn is_gnu_extension_dwarf_package_format(&self) -> bool;

    /// Returns index version of DWARF package for this `Encoding`.
    fn dwarf_package_index_version(&self) -> u16;

    /// Returns `true` if the dwarf package index version provided is compatible with this
    /// `Encoding`.
    fn is_compatible_dwarf_package_index_version(&self, index_version: u16) -> bool;
}

impl PackageFormatExt for Encoding {
    fn is_gnu_extension_dwarf_package_format(&self) -> bool {
        !self.is_std_dwarf_package_format()
    }

    fn is_std_dwarf_package_format(&self) -> bool {
        self.version >= 5
    }

    fn dwarf_package_index_version(&self) -> u16 {
        if self.is_gnu_extension_dwarf_package_format() {
            2
        } else {
            5
        }
    }

    fn is_compatible_dwarf_package_index_version(&self, index_version: u16) -> bool {
        if self.is_gnu_extension_dwarf_package_format() {
            index_version == 2
        } else {
            index_version >= 5
        }
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

macro_rules! generate_append_for {
    ( $( $fn_name:ident => ($name:ident, $section_name:expr) ),+ ) => {
        $(
            fn $fn_name(&mut self, data: &[u8]) -> Option<Contribution> {
                if data.is_empty() {
                    return None;
                }

                let id = if self.$name.is_none() {
                    let id = self.obj.add_section(
                        Vec::new(),
                        Vec::from($section_name),
                        SectionKind::Debug,
                    );
                    self.$name = Some(id);
                    id
                } else {
                    // UNWRAP: checked above
                    self.$name.unwrap()
                };

                // FIXME: correct alignment
                let offset = self.obj.append_section_data(id, data, 1);
                debug!(?offset, ?data);
                Some(Contribution {
                    offset: ContributionOffset(offset),
                    size: data.len().try_into().expect("data size larger than u64"),
                })
            }
        )+
    };
}

impl<'file> DwarfPackageObject<'file> {
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

    pub(crate) fn finish(self) -> WritableObject<'file> {
        self.obj
    }
}

/// In-progress DWARF package being produced.
pub(crate) struct InProgressDwarfPackage<'file> {
    /// Endianness of the DWARF package being created.
    endian: RunTimeEndian,

    /// Object file being created.
    obj: DwarfPackageObject<'file>,
    /// In-progress string table being accumulated. Used to write final `.debug_str.dwo` and
    /// `.debug_str_offsets.dwo` for each DWARF object.
    string_table: PackageStringTable<RunTimeEndian>,

    /// Compilation unit index entries (offsets + sizes) being accumulated.
    cu_index_entries: Vec<CuIndexEntry>,
    /// Type unit index entries (offsets + sizes) being accumulated.
    tu_index_entries: Vec<TuIndexEntry>,

    /// `DebugTypeSignature`s of type units and `DwoId`s of compilation units that have already
    /// been added to the output package.
    ///
    /// Used when adding new TU index entries to de-duplicate type units (as required by the
    /// specification). Also used to check that all dwarf objects referenced by executables
    /// have been found.
    contained_units: HashSet<DwarfObjectIdentifier>,
}

impl<'file> InProgressDwarfPackage<'file> {
    /// Create an object file with empty sections that will be later populated from DWARF object
    /// files.
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(
        architecture: object::Architecture,
        endianness: object::Endianness,
    ) -> InProgressDwarfPackage<'file> {
        let obj = DwarfPackageObject::new(architecture, endianness);

        let endian = runtime_endian_from_endianness(endianness);
        let string_table = PackageStringTable::new(endian);

        Self {
            obj,
            endian,
            string_table,
            cu_index_entries: Default::default(),
            tu_index_entries: Default::default(),
            contained_units: Default::default(),
        }
    }

    /// Returns the units contained within this in-progress DWARF package.
    pub(crate) fn contained_units(&self) -> &HashSet<DwarfObjectIdentifier> {
        &self.contained_units
    }

    /// Return the contents of a section from the input DWARF object.
    #[tracing::instrument(level = "trace", skip(sess, input))]
    fn section_data<'input, 'session: 'input>(
        &mut self,
        sess: &'session impl Session<RelocationMap>,
        input: &object::File<'input>,
        input_id: gimli::SectionId,
    ) -> object::Result<Option<&'input [u8]>> {
        let name = dwo_name(input_id);
        match input.section_by_name(name) {
            Some(section) => {
                let data = section.compressed_data()?.decompress()?;
                let data_ref = sess.alloc_owned_cow(data);
                Ok(Some(data_ref))
            }
            None => {
                trace!("section doesn't exist");
                Ok(None)
            }
        }
    }

    /// Append a unit from the input DWARF object to the `.debug_info` (or `.debug_types`) section
    /// in the output object. Only appends unit if it has a `DwarfObjectIdentifier` matching the
    /// target `DwarfObjectIdentifier`.
    #[tracing::instrument(
        level = "trace",
        skip(sess, section, unit, append_cu_contribution, append_tu_contribution)
    )]
    fn append_unit<'input, 'session: 'input, CuOp, Sect, TuOp>(
        &mut self,
        sess: &'session impl Session<RelocationMap>,
        encoding: Encoding,
        section: &Sect,
        unit: &gimli::Unit<DwpReader<'input>>,
        mut append_cu_contribution: CuOp,
        mut append_tu_contribution: TuOp,
    ) -> Result<()>
    where
        CuOp: FnMut(&mut Self, DwoId, Contribution) -> Result<()>,
        TuOp: FnMut(&mut Self, DebugTypeSignature, Contribution) -> Result<()>,
        Sect: CompressedDataRangeExt<'input, 'session>,
    {
        let size: u64 = unit
            .header
            .length_including_self()
            .try_into()
            .expect("unit header length bigger than u64");
        let offset = unit.header.offset();

        let identifier = dwo_identifier_of_unit(&unit);
        match (unit.header.type_(), identifier) {
            (
                UnitType::Compilation | UnitType::SplitCompilation(..),
                Some(DwarfObjectIdentifier::Compilation(dwo_id)),
            ) => {
                debug!(?dwo_id, "compilation unit");
                if self.contained_units.contains(&DwarfObjectIdentifier::Compilation(dwo_id)) {
                    return Err(Error::DuplicateUnit(dwo_id.0));
                }

                let offset = offset
                    .as_debug_info_offset()
                    .expect("offset from `.debug_info.dwo` section is not a `DebugInfoOffset`")
                    .0;
                let data = section
                    .compressed_data_range(sess, offset.try_into().unwrap(), size)
                    .map_err(Error::DecompressData)?
                    .ok_or(Error::EmptyUnit(dwo_id.0))?;

                if !data.is_empty() {
                    let contribution = self.obj.append_to_debug_info(data).unwrap();
                    append_cu_contribution(self, dwo_id, contribution)?;
                    self.contained_units.insert(DwarfObjectIdentifier::Compilation(dwo_id));
                }

                Ok(())
            }
            (
                UnitType::Type { .. } | UnitType::SplitType { .. },
                Some(DwarfObjectIdentifier::Type(type_signature)),
            ) => {
                debug!(?type_signature, "type unit");
                if self.contained_units.contains(&DwarfObjectIdentifier::Type(type_signature)) {
                    // Return early if a unit with this type signature has already been seen.
                    debug!(?type_signature, "skipping, already seen");
                    return Ok(());
                }

                let offset = if encoding.is_gnu_extension_dwarf_package_format() {
                    offset
                        .as_debug_types_offset()
                        .expect(
                            "offset from `.debug_types.dwo` section is not a `DebugTypesOffset`",
                        )
                        .0
                } else {
                    offset
                        .as_debug_info_offset()
                        .expect("offset from `.debug_info.dwo` section is not a `DebugInfoOffset`")
                        .0
                };
                let data = section
                    .compressed_data_range(sess, offset.try_into().unwrap(), size)
                    .map_err(Error::DecompressData)?
                    .ok_or(Error::EmptyUnit(type_signature.0))?;

                if !data.is_empty() {
                    let contribution = if encoding.is_gnu_extension_dwarf_package_format() {
                        self.obj.append_to_debug_types(data).unwrap()
                    } else {
                        self.obj.append_to_debug_info(data).unwrap()
                    };
                    append_tu_contribution(self, type_signature, contribution)?;
                    self.contained_units.insert(DwarfObjectIdentifier::Type(type_signature));
                }

                Ok(())
            }
            (_, Some(..)) => {
                debug!("unit in dwarf object is not a split unit, skipping");
                Ok(())
            }
            (_, None) => Ok(()),
        }
    }

    /// Process a DWARF object. Copies relevant sections, compilation/type units and strings from
    /// DWARF object into output object.
    #[tracing::instrument(level = "trace", skip(sess, input, input_dwarf))]
    pub(crate) fn append_dwarf_object<'input, 'session: 'input>(
        &mut self,
        sess: &'session impl Session<RelocationMap>,
        input: &object::File<'input>,
        input_dwarf: &gimli::Dwarf<DwpReader<'input>>,
        encoding: Encoding,
    ) -> Result<()> {
        use gimli::SectionId::*;

        // Load index sections (if they exist).
        let cu_index = maybe_load_index_section::<_, gimli::DebugCuIndex<_>, _, _>(
            sess,
            encoding,
            self.endian,
            input,
        )?;
        let tu_index = maybe_load_index_section::<_, gimli::DebugTuIndex<_>, _, _>(
            sess,
            encoding,
            self.endian,
            input,
        )?;

        // Concatenate contents of sections from the DWARF object into the corresponding section in
        // the output.
        let debug_abbrev = self
            .section_data(sess, &input, DebugAbbrev)?
            .and_then(|data| self.obj.append_to_debug_abbrev(data))
            .ok_or(Error::MissingRequiredSection(".debug_abbrev.dwo"))?;
        let debug_line = self
            .section_data(sess, &input, DebugLine)?
            .and_then(|data| self.obj.append_to_debug_line(data));
        let debug_macro = self
            .section_data(sess, &input, DebugMacro)?
            .and_then(|data| self.obj.append_to_debug_macro(data));

        let (debug_loc, debug_macinfo, debug_loclists, debug_rnglists) =
            if encoding.is_gnu_extension_dwarf_package_format() {
                // Only `.debug_loc.dwo` and `.debug_macinfo.dwo` with the GNU extension.
                let debug_loc = self
                    .section_data(sess, &input, DebugLoc)?
                    .and_then(|data| self.obj.append_to_debug_loc(data));
                let debug_macinfo = self
                    .section_data(sess, &input, DebugMacinfo)?
                    .and_then(|data| self.obj.append_to_debug_macinfo(data));
                (debug_loc, debug_macinfo, None, None)
            } else {
                // Only `.debug_loclists.dwo` and `.debug_rnglists.dwo` with DWARF 5.
                let debug_loclists = self
                    .section_data(sess, &input, DebugLocLists)?
                    .and_then(|data| self.obj.append_to_debug_loclists(data));
                let debug_rnglists = self
                    .section_data(sess, &input, DebugRngLists)?
                    .and_then(|data| self.obj.append_to_debug_rnglists(data));
                (None, None, debug_loclists, debug_rnglists)
            };

        // Concatenate string offsets from the DWARF object into the `.debug_str_offsets` section
        // in the output, rewriting offsets to be based on the new, merged string table.
        let debug_str_offsets =
            if let Some(section) = input.section_by_name(".debug_str_offsets.dwo") {
                let data = section.compressed_data()?.decompress()?;
                let data_ref = sess.alloc_owned_cow(data);
                let debug_str_offsets =
                    gimli::DebugStrOffsets::from(gimli::EndianSlice::new(data_ref, self.endian));

                let debug_str = if let Some(section) = input.section_by_name(".debug_str.dwo") {
                    let data = section.compressed_data()?.decompress()?;
                    let data_ref = sess.alloc_owned_cow(data);
                    gimli::DebugStr::new(data_ref, self.endian)
                } else {
                    return Err(Error::MissingRequiredSection(".debug_str.dwo"));
                };

                let debug_str_offsets_data = self.string_table.remap_str_offsets_section(
                    debug_str,
                    debug_str_offsets,
                    section.size(),
                    self.endian,
                    encoding,
                )?;
                self.obj.append_to_debug_str_offsets(debug_str_offsets_data.slice())
            } else {
                None
            };

        // Create offset adjustor functions, see comment on `create_contribution_adjustor` for
        // explanation.
        let mut abbrev_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugAbbrev);
        let mut line_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugLine);
        let mut loc_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugLoc);
        let mut loclists_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugLocLists);
        let mut rnglists_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugRngLists);
        let mut str_offsets_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugStrOffsets);
        let mut macinfo_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugMacinfo);
        let mut macro_cu_adjustor =
            create_contribution_adjustor(cu_index.as_ref(), gimli::SectionId::DebugMacro);

        let mut abbrev_tu_adjustor =
            create_contribution_adjustor(tu_index.as_ref(), gimli::SectionId::DebugAbbrev);
        let mut line_tu_adjustor =
            create_contribution_adjustor(tu_index.as_ref(), gimli::SectionId::DebugLine);
        let mut loclists_tu_adjustor =
            create_contribution_adjustor(tu_index.as_ref(), gimli::SectionId::DebugLocLists);
        let mut rnglists_tu_adjustor =
            create_contribution_adjustor(tu_index.as_ref(), gimli::SectionId::DebugRngLists);
        let mut str_offsets_tu_adjustor =
            create_contribution_adjustor(tu_index.as_ref(), gimli::SectionId::DebugStrOffsets);

        // UNWRAP: `dwo_name` has known return value for this section.
        let debug_info_name = gimli::SectionId::DebugInfo.dwo_name().unwrap();
        let debug_info_section = input
            .section_by_name(debug_info_name)
            .ok_or(Error::MissingRequiredSection(".debug_info.dwo"))?;

        // Append compilation (and type units, in DWARF 5) from `.debug_info`.
        let mut iter = input_dwarf.units();
        while let Some(header) = iter.next().map_err(Error::ParseUnitHeader)? {
            let unit = input_dwarf.unit(header).map_err(Error::ParseUnit)?;
            self.append_unit(
                sess,
                encoding,
                &debug_info_section,
                &unit,
                |this, dwo_id, debug_info| {
                    let debug_abbrev = abbrev_cu_adjustor(dwo_id, Some(debug_abbrev))?
                        .expect("mandatory section cannot be adjusted");
                    let debug_line = line_cu_adjustor(dwo_id, debug_line)?;
                    let debug_loc = loc_cu_adjustor(dwo_id, debug_loc)?;
                    let debug_loclists = loclists_cu_adjustor(dwo_id, debug_loclists)?;
                    let debug_rnglists = rnglists_cu_adjustor(dwo_id, debug_rnglists)?;
                    let debug_str_offsets = str_offsets_cu_adjustor(dwo_id, debug_str_offsets)?;
                    let debug_macinfo = macinfo_cu_adjustor(dwo_id, debug_macinfo)?;
                    let debug_macro = macro_cu_adjustor(dwo_id, debug_macro)?;

                    this.cu_index_entries.push(CuIndexEntry {
                        encoding,
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
                    let debug_abbrev = abbrev_tu_adjustor(type_sig, Some(debug_abbrev))?
                        .expect("mandatory section cannot be adjusted");
                    let debug_line = line_tu_adjustor(type_sig, debug_line)?;
                    let debug_loclists = loclists_tu_adjustor(type_sig, debug_loclists)?;
                    let debug_rnglists = rnglists_tu_adjustor(type_sig, debug_rnglists)?;
                    let debug_str_offsets = str_offsets_tu_adjustor(type_sig, debug_str_offsets)?;

                    this.tu_index_entries.push(TuIndexEntry {
                        encoding,
                        type_signature: type_sig,
                        debug_info_or_types: debug_info,
                        debug_abbrev,
                        debug_line,
                        debug_loclists,
                        debug_rnglists,
                        debug_str_offsets,
                    });
                    Ok(())
                },
            )?;
        }

        // Append type units from `.debug_info` with the GNU extension.
        if encoding.is_gnu_extension_dwarf_package_format() {
            // UNWRAP: `dwo_name` has known return value for this section.
            let debug_types_name = gimli::SectionId::DebugTypes.dwo_name().unwrap();
            if let Some(debug_types_section) = input.section_by_name(debug_types_name) {
                let mut iter = input_dwarf.type_units();
                while let Some(header) = iter.next().map_err(Error::ParseUnitHeader)? {
                    let unit = input_dwarf.unit(header).map_err(Error::ParseUnit)?;
                    self.append_unit(
                        sess,
                        encoding,
                        &debug_types_section,
                        &unit,
                        |_, _, _| {
                            /* no-op, no compilation units in `.debug_types` */
                            Ok(())
                        },
                        |this, type_sig, debug_info_or_types| {
                            let debug_abbrev = abbrev_tu_adjustor(type_sig, Some(debug_abbrev))?
                                .expect("mandatory section cannot be adjusted");
                            let debug_line = line_tu_adjustor(type_sig, debug_line)?;
                            let debug_loclists = loclists_tu_adjustor(type_sig, debug_loclists)?;
                            let debug_rnglists = rnglists_tu_adjustor(type_sig, debug_rnglists)?;
                            let debug_str_offsets =
                                str_offsets_tu_adjustor(type_sig, debug_str_offsets)?;

                            this.tu_index_entries.push(TuIndexEntry {
                                encoding,
                                type_signature: type_sig,
                                debug_info_or_types,
                                debug_abbrev,
                                debug_line,
                                debug_loclists,
                                debug_rnglists,
                                debug_str_offsets,
                            });
                            Ok(())
                        },
                    )?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn finish(self) -> Result<WritableObject<'file>> {
        let Self { mut obj, string_table, cu_index_entries, tu_index_entries, .. } = self;

        // Write `.debug_str` to the object.
        let _ = obj.append_to_debug_str(string_table.finish().slice());

        // Write `.debug_{cu,tu}_index` sections to the object.
        debug!("writing cu index");
        let cu_index_data = cu_index_entries.write_index(self.endian)?;
        let _ = obj.append_to_debug_cu_index(cu_index_data.slice());
        debug!("writing tu index");
        let tu_index_data = tu_index_entries.write_index(self.endian)?;
        let _ = obj.append_to_debug_tu_index(tu_index_data.slice());

        Ok(obj.finish())
    }
}

impl<'file> fmt::Debug for InProgressDwarfPackage<'file> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InProgressDwarfPackage")
    }
}
