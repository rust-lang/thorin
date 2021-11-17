use crate::relocate::{add_relocations, Relocate, RelocationMap};
use anyhow::{anyhow, Context, Result};
use gimli::{
    write::{EndianVec, Writer},
    DebugAddr, DebugStrOffset, DebugStrOffsetsBase, DebugStrOffsetsIndex, DwarfFileType,
    EndianSlice, Format, Reader, RunTimeEndian, UnitType,
};
use indexmap::IndexSet;
use memmap2::Mmap;
use object::{
    write::{self, SectionId, StreamingBuffer},
    Architecture, BinaryFormat, Endianness, Object, ObjectSection, SectionKind,
};
use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use thiserror::Error;
use tracing::{debug, trace};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;
use typed_arena::Arena;

mod relocate;

type DwpReader<'arena> = Relocate<'arena, EndianSlice<'arena, RunTimeEndian>>;

#[derive(Debug, Error)]
enum DwpError {
    #[error("compilation unit with dwo id has no dwo name")]
    DwoIdWithoutDwoName,
    #[error("missing compilation unit die")]
    MissingUnitDie,
    #[error("section without name at offset 0x{0:08x}")]
    SectionWithoutName(usize),
    #[error("relocation with invalid symbol for section {0} at offset 0x{1:08x}")]
    RelocationWithInvalidSymbol(String, usize),
    #[error("multiple relocations for section {0} at offset 0x{1:08x}")]
    MultipleRelocations(String, usize),
    #[error("unsupported relocation for section {0} at offset 0x{1:08x}")]
    UnsupportedRelocation(String, usize),
    #[error("missing {0} section in dwarf object")]
    DwarfObjectMissingSection(String),
    #[error("failed to create output file")]
    FailedToCreateOutputFile,
    #[error("dwarf object has no units")]
    DwarfObjectWithNoUnits,
    #[error("str offset value out of range of entry size")]
    DwpStrOffsetOutOfRange,
    #[error("compilation unit in dwarf object with dwo id is not a split unit")]
    DwarfObjectCompilationUnitWithDwoIdNotSplitUnit,
    #[error("compilation unit in dwarf object with no data")]
    CompilationUnitWithNoData,
}

/// In-progress DWARF package output being produced.
struct DwpOutputObject<'file> {
    /// Object file being created.
    obj: write::Object<'file>,
    /// Identifier for the `.debug_abbrev.dwo` section in the object file being created.
    debug_abbrev: SectionId,
    /// Identifier for the `.debug_line.dwo` section in the object file being created.
    debug_line: SectionId,
    /// Identifier for the `.debug_loclists.dwo` section in the object file being created.
    debug_loclists: SectionId,
    /// Identifier for the `.debug_rnglists.dwo` section in the object file being created.
    debug_rnglists: SectionId,
    /// Identifier for the `.debug_str.dwo` section in the object file being created.
    debug_str: SectionId,
    /// Identifier for the `.debug_str_offsets.dwo` section in the object file being created.
    debug_str_offsets: SectionId,
    /// Identifier for the `.debug_info.dwo` section in the object file being created.
    debug_info: SectionId,
    /// Identifier for the `.debug_cu_index.dwo` section in the object file being created.
    debug_cu_index: SectionId,
}

/// A DWARF object referenced by input object.
struct TargetDwarfObject {
    /// `DwoId` of the DWARF object, read from compilation unit header or `DW_AT_GNU_dwo_id`.
    dwo_id: DwoId,
    /// Path to the DWARF object, read from `DW_AT_dwo_name`/`DW_AT_GNU_dwo_name`, prepended with
    /// `DW_AT_comp_dir`.
    path: PathBuf,
}

impl fmt::Debug for TargetDwarfObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x} ({})",
            self.dwo_id.0,
            self.path
                .file_name()
                .expect("target dwarf object path w/out filename")
                .to_str()
                .expect("target dwarf object filename has invalid unicode")
        )
    }
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
struct DwoId(u64);

impl fmt::Debug for DwoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DwoId({:#x})", self.0)
    }
}

impl From<gimli::DwoId> for DwoId {
    fn from(dwo_id: gimli::DwoId) -> DwoId {
        DwoId(dwo_id.0)
    }
}

/// New-type'd index from `IndexVec` of strings inserted into the `.debug_str` section.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct DwpStringId(usize);

/// DWARF packages need to merge the `.debug_str` sections of input DWARF objects.
/// `.debug_str_offsets` sections then need to be rebuilt with offsets into the new merged
/// `.debug_str` section and then concatenated (indices into each dwarf object's offset list will
/// therefore still refer to the same string).
///
/// Gimli's `StringTable` produces a `.debug_str` section with a single `.debug_str_offsets`
/// section, but `DwpStringTable` accumulates a single `.debug_str` section and can be used to
/// produce multiple `.debug_str_offsets` sections (which will be concatenated) which all offset
/// into the same `.debug_str`.
struct DwpStringTable<E: gimli::Endianity> {
    debug_str: gimli::write::DebugStr<EndianVec<E>>,
    strings: IndexSet<Vec<u8>>,
    offsets: HashMap<DwpStringId, DebugStrOffset>,
}

impl<E: gimli::Endianity> DwpStringTable<E> {
    /// Create a new `DwpStringTable` with a given endianity.
    fn new(endianness: E) -> Self {
        Self {
            debug_str: gimli::write::DebugStr(EndianVec::new(endianness)),
            strings: IndexSet::new(),
            offsets: HashMap::new(),
        }
    }

    /// Insert a string into the string table and return its offset in the table. If the string is
    /// already in the table, returns its offset.
    fn get_or_insert<T: Into<Vec<u8>>>(&mut self, bytes: T) -> Result<DebugStrOffset> {
        let bytes = bytes.into();
        assert!(!bytes.contains(&0));
        let (index, is_new) = self.strings.insert_full(bytes.clone());
        let index = DwpStringId(index);
        if !is_new {
            return Ok(*self.offsets.get(&index).expect("insert exists but no offset"));
        }

        // Keep track of the offset for this string, it might be referenced by the next compilation
        // unit too.
        let offset = self.debug_str.offset();
        self.offsets.insert(index, offset);

        // Insert into the string table.
        self.debug_str.write(&bytes)?;
        self.debug_str.write_u8(0)?;

        Ok(offset)
    }

    /// Write the accumulated `.debug_str` section to an object file, returns the offset of the
    /// section in the object.
    fn write<'file>(self, obj: &mut write::Object<'file>, section: SectionId) -> u64 {
        // FIXME: what is the correct way to determine this alignment
        obj.append_section_data(section, &self.debug_str.0.into_vec(), 1)
    }
}

/// Helper trait for types that can be used in creating the `.debug_{cu,tu}_index` hash table.
trait Bucketable {
    fn index(&self) -> u64;
}

/// New-type'd offset into a section of a compilation/type unit's contribution.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
struct ContributionOffset(u64);

impl fmt::Debug for ContributionOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContributionOffset({:#x})", self.0)
    }
}

/// Type alias for the size of a compilation/type unit's contribution.
type ContributionSize = u64;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct Contribution {
    offset: ContributionOffset,
    size: ContributionSize,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct CuIndexEntry {
    dwo_id: DwoId,
    info: Contribution,
    abbrev: Contribution,
    loc: Option<Contribution>,
    line: Option<Contribution>,
    str_off: Option<Contribution>,
    rng: Option<Contribution>,
}

impl CuIndexEntry {
    /// Return the number of columns in `.debug_cu_index` required by this entry.
    fn number_of_columns(&self) -> u32 {
        2 /* info and abbrev are required columns */
            + self.loc.map_or(0, |_| 1)
            + self.line.map_or(0, |_| 1)
            + self.str_off.map_or(0, |_| 1)
            + self.rng.map_or(0, |_| 1)
    }
}

impl Bucketable for CuIndexEntry {
    fn index(&self) -> u64 {
        self.dwo_id.0
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "rust-dwp", about = "merge split dwarf (.dwo) files")]
struct Opt {
    /// Specify the executable/library files to get the list of *.dwo from
    #[structopt(short = "e", long = "exec", parse(from_os_str))]
    executable: PathBuf,
    /// Specify the path to write the packaged dwp file to
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    output: PathBuf,
}

/// Load and parse an object file.
#[tracing::instrument(level = "trace", skip(arena_mmap))]
fn load_object_file<'input, 'arena: 'input>(
    arena_mmap: &'arena Arena<Mmap>,
    path: &'input Path,
) -> Result<object::File<'arena>> {
    let file = fs::File::open(&path)
        .with_context(|| format!("failed to open object file at {}", path.display()))?;

    let mmap = (unsafe { Mmap::map(&file) })
        .with_context(|| format!("failed to map file at {}", path.display()))?;

    let mmap_ref = (*arena_mmap.alloc(mmap)).borrow();
    object::File::parse(&**mmap_ref)
        .with_context(|| format!("failed to parse file at {}", path.display()))
}

/// Returns the `RunTimeEndian` which matches the endianness of the object file.
fn runtime_endian_of_object<'a>(obj: &object::File<'a>) -> RunTimeEndian {
    if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    }
}

/// Loads a section of a file from `object::File` into a `gimli::EndianSlice`. Expected to be
/// curried using a closure and provided to `Dwarf::load`.
#[tracing::instrument(level = "trace", skip(obj, arena_data, arena_relocations))]
fn load_file_section<'input, 'arena: 'input>(
    id: gimli::SectionId,
    obj: &object::File<'input>,
    is_dwo: bool,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<DwpReader<'arena>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo { id.dwo_name() } else { Some(id.name()) };

    let data = match name.and_then(|name| obj.section_by_name(&name)) {
        Some(ref section) => {
            if !is_dwo {
                add_relocations(&mut relocations, obj, section)?;
            }
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };

    let data_ref = (*arena_data.alloc(data)).borrow();
    let reader = gimli::EndianSlice::new(data_ref, runtime_endian_of_object(obj));
    let section = reader;
    let relocations = (*arena_relocations.alloc(relocations)).borrow();
    Ok(Relocate { relocations, section, reader })
}

/// Returns the `DwoId` of a DIE.
///
/// With DWARF 5, `DwoId` is in the unit header of a skeleton unit (identifying the split
/// compilation unit that contains the debuginfo) or split compilation unit (identifying the
/// skeleton unit that this debuginfo corresponds to). In earlier DWARF versions with GNU extension,
/// `DW_AT_GNU_dwo_id` attribute of the DIE contains the `DwoId`.
#[tracing::instrument(level = "trace", skip(unit))]
fn dwo_id_of_unit<R: gimli::Reader>(unit: &gimli::Unit<R>) -> Option<DwoId> {
    match unit.header.type_() {
        // DWARF 5
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => Some(dwo_id.into()),
        // GNU Extension (maybe!)
        UnitType::Compilation => unit.dwo_id.map(|id| id.into()),
        // Wrong compilation unit type.
        _ => None,
    }
}

/// Returns the `DwoId` and `PathBuf` of a DIE.
///
/// See `dwo_id_of_unit` for detailed description of `DwoId` source. With DWARF 5, skeleton
/// compilation unit will contain a `DW_AT_dwo_name` attribute with the name of the dwarf object
/// file containing the split compilation unit with the `DwoId`. In earlier DWARF
/// versions with GNU extension, `DW_AT_GNU_dwo_name` attribute contains name.
#[tracing::instrument(level = "trace", skip(dwarf, unit))]
fn dwo_id_and_path_of_unit<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
) -> Result<Option<TargetDwarfObject>> {
    let dwo_id = if let Some(dwo_id) = dwo_id_of_unit(unit) {
        dwo_id
    } else {
        return Ok(None);
    };

    let dwo_name = {
        let mut cursor = unit.header.entries(&unit.abbreviations);
        cursor.next_dfs()?;
        let root = cursor.current().ok_or(anyhow!(DwpError::MissingUnitDie))?;

        let dwo_name = if let Some(val) = root.attr_value(gimli::DW_AT_dwo_name)? {
            // DWARF 5
            val
        } else if let Some(val) = root.attr_value(gimli::DW_AT_GNU_dwo_name)? {
            // GNU Extension
            val
        } else {
            return Err(anyhow!(DwpError::DwoIdWithoutDwoName));
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

    Ok(Some(TargetDwarfObject { dwo_id, path }))
}

/// Parse the executable and return the `.debug_addr` section and the referenced DWARF objects.
///
/// Loading DWARF objects requires the `.debug_addr` section from the parent object. DWARF objects
/// that need to be loaded are accumulated from the skeleton compilation units in the executable's
/// DWARF, their `DwoId` and constructed paths are collected.
#[tracing::instrument(level = "trace", skip(obj, arena_data, arena_relocations))]
fn parse_executable<'input, 'arena: 'input>(
    obj: &object::File<'input>,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<(DebugAddr<DwpReader<'arena>>, Vec<TargetDwarfObject>)> {
    let mut dwarf_objects = Vec::new();

    let mut load_section = |id: gimli::SectionId| -> Result<_> {
        load_file_section(id, &obj, false, &arena_data, &arena_relocations)
    };

    let dwarf = gimli::Dwarf::load(&mut load_section)?;
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        if let Some(dwo) = dwo_id_and_path_of_unit(&dwarf, &unit)? {
            dwarf_objects.push(dwo);
        }
    }

    Ok((dwarf.debug_addr, dwarf_objects))
}

/// Create an object file with empty sections that will be later populated from DWARF object files.
///
/// In DWARF 5, DWARF package files have nine sections: `.debug_abbrev.dwo`, `.debug_info.dwo`,
/// `.debug_rnglists.dwo`, `.debug_loclists.dwo`, `.debug_line.dwo`, `.debug_str_offsets.dwo`,
/// `.debug_str.dwo`, `.debug_cu_index` and `.debug_tu_index`
#[tracing::instrument(level = "trace")]
fn create_output_object<'file>(
    architecture: Architecture,
    endianness: Endianness,
) -> Result<DwpOutputObject<'file>> {
    let mut obj = write::Object::new(BinaryFormat::Elf, architecture, endianness);

    let mut add_section = |gimli_id: gimli::SectionId| -> SectionId {
        obj.add_section(
            Vec::new(),
            gimli_id.dwo_name().unwrap().as_bytes().to_vec(),
            SectionKind::Debug,
        )
    };

    let debug_abbrev = add_section(gimli::SectionId::DebugAbbrev);
    let debug_line = add_section(gimli::SectionId::DebugLine);
    let debug_loclists = add_section(gimli::SectionId::DebugLocLists);
    let debug_rnglists = add_section(gimli::SectionId::DebugRngLists);
    let debug_str = add_section(gimli::SectionId::DebugStr);
    let debug_str_offsets = add_section(gimli::SectionId::DebugStrOffsets);
    let debug_info = add_section(gimli::SectionId::DebugInfo);
    let debug_cu_index = add_section(gimli::SectionId::DebugCuIndex);

    Ok(DwpOutputObject {
        obj,
        debug_abbrev,
        debug_line,
        debug_loclists,
        debug_rnglists,
        debug_str,
        debug_str_offsets,
        debug_info,
        debug_cu_index,
    })
}

/// Read the string offsets from `.debug_str_offsets.dwo` in the DWARF object, adding each to the
/// in-progress `.debug_str` (`DwpStringTable`) and building a new `.debug_str_offsets.dwo` to be
/// the current DWARF object's contribution to the DWARF package.
#[tracing::instrument(level = "trace", skip(dwo_obj, dwo_dwarf, string_table, output))]
fn append_str_offsets<'input, 'output, 'arena: 'input, Endian: gimli::Endianity>(
    dwo_obj: &object::File<'input>,
    dwo_dwarf: &gimli::Dwarf<DwpReader<'arena>>,
    string_table: &mut DwpStringTable<Endian>,
    output: &mut DwpOutputObject<'output>,
) -> Result<Option<Contribution>> {
    let section_name = gimli::SectionId::DebugStrOffsets.dwo_name().unwrap();
    let section = match dwo_obj.section_by_name(section_name) {
        Some(section) => section,
        // `.debug_str_offsets.dwo` is an optional section.
        None => return Ok(None),
    };
    let section_size = section.size();

    let mut data = EndianVec::new(runtime_endian_of_object(dwo_obj));

    let root_header = dwo_dwarf.units().next()?.context(DwpError::DwarfObjectWithNoUnits)?;
    let encoding = root_header.encoding();
    let base = DebugStrOffsetsBase::default_for_encoding_and_file(encoding, DwarfFileType::Dwo);

    let entry_size = match encoding.format {
        Format::Dwarf32 => 4,
        Format::Dwarf64 => 8,
    };

    debug!(?section_size, str_offset_size_num_elements = section_size / entry_size);
    for i in 0..(section_size / entry_size) {
        let dwo_index = DebugStrOffsetsIndex(i as usize);
        let dwo_offset =
            dwo_dwarf.debug_str_offsets.get_str_offset(encoding.format, base, dwo_index)?;
        let dwo_str = dwo_dwarf.debug_str.get_str(dwo_offset)?;
        let dwo_str = dwo_str.to_string()?;

        let dwp_offset = string_table.get_or_insert(dwo_str.as_ref())?;
        debug!(?i, ?dwo_str, "dwo_offset={:#x} dwp_offset={:#x}", dwo_offset.0, dwp_offset.0);

        match encoding.format {
            Format::Dwarf32 => {
                data.write_u32(dwp_offset.0.try_into().context(DwpError::DwpStrOffsetOutOfRange)?)?;
            }
            Format::Dwarf64 => {
                data.write_u64(dwp_offset.0.try_into().context(DwpError::DwpStrOffsetOutOfRange)?)?;
            }
        }
    }

    let offset =
        output.obj.append_section_data(output.debug_str_offsets, &data.into_vec(), section.align());
    Ok(Some(Contribution {
        offset: ContributionOffset(offset),
        size: section_size.try_into().expect("too large for u32"),
    }))
}

/// Append a unit from the input DWARF object to the `.debug_info` (or `.debug_types`) section in
/// the output object. Only appends unit if it has a `DwoId` matching the target `DwoId`.
#[tracing::instrument(level = "trace", skip(debug_info, unit, output, create_cu_entry))]
fn append_unit<'input, 'arena, 'output: 'arena, CuOp, Sect>(
    dwo: &TargetDwarfObject,
    debug_info: &Sect,
    unit: &gimli::Unit<DwpReader<'arena>>,
    output: &mut DwpOutputObject<'output>,
    mut create_cu_entry: CuOp,
) -> Result<()>
where
    CuOp: FnMut(DwoId, Contribution),
    Sect: ObjectSection<'input>,
{
    // Split compilation unit corresponding to previously found skeleton compilation unit.
    let dwo_id = dwo_id_of_unit(&unit);
    match (dwo_id, unit.header.type_()) {
        (Some(dwo_id), UnitType::Compilation | UnitType::SplitCompilation(..))
            if dwo_id == dwo.dwo_id =>
        {
            let dwo_length: u64 = unit.header.length_including_self().try_into().unwrap();

            let dwo_offset = unit.header.offset().as_debug_info_offset().unwrap().0;
            let dwo_data = debug_info
                .data_range(dwo_offset.try_into().unwrap(), dwo_length)?
                .ok_or(DwpError::CompilationUnitWithNoData)?;
            let dwp_offset =
                output.obj.append_section_data(output.debug_info, dwo_data, debug_info.align());

            create_cu_entry(
                dwo_id,
                Contribution { offset: ContributionOffset(dwp_offset), size: dwo_length },
            );

            Ok(())
        }
        (Some(..), _) => Err(anyhow!(DwpError::DwarfObjectCompilationUnitWithDwoIdNotSplitUnit)),
        _ => Ok(()),
    }
}

/// Append the contents of a section from the input DWARF object to the equivalent section in the
/// output object.
#[tracing::instrument(level = "trace", skip(input, output))]
fn append_section<'input, 'output>(
    input: &object::File<'input>,
    input_id: gimli::SectionId,
    output: &mut write::Object<'output>,
    output_id: SectionId,
    required: bool,
) -> Result<Option<Contribution>> {
    let name = input_id.dwo_name().unwrap();
    match input.section_by_name(name) {
        Some(section) => {
            let size = section.size();
            let offset = output.append_section_data(output_id, &section.data()?, section.align());

            Ok(Some(Contribution { offset: ContributionOffset(offset), size }))
        }
        None if required => Err(anyhow!(DwpError::DwarfObjectMissingSection(name.to_string()))),
        None => Ok(None),
    }
}

/// Process a DWARF object. Copies relevant sections, compilation/type units and strings from DWARF
/// object into output object.
#[tracing::instrument(
    level = "trace",
    skip(parent_debug_addr, string_table, output, arena_data, arena_mmap, arena_relocations)
)]
fn process_dwarf_object<'input, 'output, 'arena: 'input, Endian: gimli::Endianity>(
    parent_debug_addr: DebugAddr<DwpReader<'arena>>,
    dwo: TargetDwarfObject,
    cu_index_entries: &mut Vec<CuIndexEntry>,
    string_table: &mut DwpStringTable<Endian>,
    output: &mut DwpOutputObject<'output>,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_mmap: &'arena Arena<Mmap>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<()> {
    let dwo_obj = load_object_file(&arena_mmap, &dwo.path)?;

    let mut load_dwo_section = |id: gimli::SectionId| -> Result<_, _> {
        load_file_section(id, &dwo_obj, true, &arena_data, &arena_relocations)
    };

    let mut dwo_dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
    dwo_dwarf.debug_addr = parent_debug_addr.clone();

    let abbrev_offset = append_section(
        &dwo_obj,
        gimli::SectionId::DebugAbbrev,
        &mut output.obj,
        output.debug_abbrev,
        true,
    )?
    .expect("required section didn't return error");
    let line_offset = append_section(
        &dwo_obj,
        gimli::SectionId::DebugLine,
        &mut output.obj,
        output.debug_line,
        false,
    )?;
    let loclists_offset = append_section(
        &dwo_obj,
        gimli::SectionId::DebugLocLists,
        &mut output.obj,
        output.debug_loclists,
        false,
    )?;
    let rnglists_offset = append_section(
        &dwo_obj,
        gimli::SectionId::DebugRngLists,
        &mut output.obj,
        output.debug_rnglists,
        false,
    )?;
    let str_offsets_offset = append_str_offsets(&dwo_obj, &dwo_dwarf, string_table, output)?;

    let debug_info_name = gimli::SectionId::DebugInfo.dwo_name().unwrap();
    let debug_info = dwo_obj
        .section_by_name(debug_info_name)
        .with_context(|| DwpError::DwarfObjectMissingSection(debug_info_name.to_string()))?;

    let mut iter = dwo_dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwo_dwarf.unit(header)?;
        append_unit(&dwo, &debug_info, &unit, output, |dwo_id, info_offset| {
            cu_index_entries.push(CuIndexEntry {
                dwo_id,
                info: info_offset,
                abbrev: abbrev_offset,
                loc: loclists_offset,
                line: line_offset,
                str_off: str_offsets_offset,
                rng: rnglists_offset,
            });
        })?;
    }

    Ok(())
}

/// Returns the next number after `val` which is a power of 2.
///
/// Invariant: `val >= 2`
#[tracing::instrument(level = "trace")]
fn next_pow2(mut val: u32) -> u32 {
    assert!(val >= 2);
    val -= 1;
    val |= val >> 1;
    val |= val >> 2;
    val |= val >> 4;
    val |= val >> 8;
    val |= val >> 16;
    val += 1;
    val
}

/// Returns a hash table computed for `elements`. Used in the `.debug_{cu,tu}_index` sections.
#[tracing::instrument(level = "trace", skip_all)]
fn bucket<B: Bucketable + fmt::Debug>(elements: &[B]) -> Vec<u32> {
    let unit_count: u32 = elements.len().try_into().expect("unit count too big for u32");
    let num_buckets = next_pow2(3 * unit_count / 2);
    let mask: u64 = num_buckets as u64 - 1;

    let mut buckets = vec![0u32; num_buckets as usize];
    let mut i = 0;
    for elem in elements {
        let s = elem.index();
        let mut h = s & mask;
        let hp = ((s >> 32) & mask) | 1;

        while buckets[h as usize] > 0 {
            assert!(elements[(buckets[h as usize] - 1) as usize].index() == elem.index());
            h = (h + hp) & mask;
        }

        buckets[h as usize] = i + 1;
        i += 1;
    }

    buckets
}

/// Write `.debug_{cu,tu}_index` to the output object.
fn write_indices<'output, E: gimli::Endianity>(
    endianness: E,
    cu_index_entries: Vec<CuIndexEntry>,
    output: &mut DwpOutputObject<'output>,
) -> Result<()> {
    let mut cu_index_data = EndianVec::new(endianness);

    let buckets = bucket(&cu_index_entries);
    debug!(?buckets);

    let has_loc = cu_index_entries.iter().all(|e| e.loc.is_some());
    let has_line = cu_index_entries.iter().all(|e| e.line.is_some());
    let has_str_off = cu_index_entries.iter().all(|e| e.str_off.is_some());
    let has_rng = cu_index_entries.iter().all(|e| e.rng.is_some());
    debug!(?has_loc, ?has_line, ?has_str_off, ?has_rng);

    let num_columns = cu_index_entries.first().unwrap().number_of_columns();
    assert!(cu_index_entries.iter().all(|e| e.number_of_columns() == num_columns));
    debug!(?num_columns);

    // DWARF 5
    cu_index_data.write_u32(2)?;
    // Reserved padding
    // FIXME: write either V5 format or V2 format
    // cu_index_data.write_u32(0)?;
    // Columns (e.g. info, abbrev, loc, etc.)
    // FIXME: only output necessary columns
    cu_index_data.write_u32(num_columns)?;
    // Number of units
    cu_index_data.write_u32(cu_index_entries.len().try_into().unwrap())?;
    // Number of buckets
    cu_index_data.write_u32(buckets.len().try_into().unwrap())?;

    // Write signatures
    for i in &buckets {
        if *i > 0 {
            cu_index_data.write_u64(cu_index_entries[(*i - 1) as usize].dwo_id.0)?;
        } else {
            cu_index_data.write_u64(0)?;
        }
    }

    // Write indices
    for i in &buckets {
        cu_index_data.write_u32(*i)?;
    }

    // Write column headers
    // FIXME: only output necessary columns
    cu_index_data.write_u32(gimli::DW_SECT_V2_INFO.0)?;
    cu_index_data.write_u32(gimli::DW_SECT_V2_ABBREV.0)?;
    if has_loc {
        cu_index_data.write_u32(gimli::DW_SECT_V2_LOC.0)?;
    }
    if has_line {
        cu_index_data.write_u32(gimli::DW_SECT_V2_LINE.0)?;
    }
    if has_str_off {
        cu_index_data.write_u32(gimli::DW_SECT_V2_STR_OFFSETS.0)?;
    }
    if has_rng {
        // FIXME: write all V2 or all V5
        cu_index_data.write_u32(gimli::DW_SECT_RNGLISTS.0)?;
    }

    // Write offsets
    for cu_index_entry in &cu_index_entries {
        cu_index_data.write_u32(cu_index_entry.info.offset.0.try_into().unwrap())?;
        cu_index_data.write_u32(cu_index_entry.abbrev.offset.0.try_into().unwrap())?;
        if has_loc {
            cu_index_data.write_u32(cu_index_entry.loc.unwrap().offset.0.try_into().unwrap())?;
        }
        if has_line {
            cu_index_data.write_u32(cu_index_entry.line.unwrap().offset.0.try_into().unwrap())?;
        }
        if has_str_off {
            cu_index_data
                .write_u32(cu_index_entry.str_off.unwrap().offset.0.try_into().unwrap())?;
        }
        if has_rng {
            cu_index_data.write_u32(cu_index_entry.rng.unwrap().offset.0.try_into().unwrap())?;
        }
    }

    // Write sizes
    for cu_index_entry in cu_index_entries {
        cu_index_data.write_u32(cu_index_entry.info.size.try_into().unwrap())?;
        cu_index_data.write_u32(cu_index_entry.abbrev.size.try_into().unwrap())?;
        if has_loc {
            cu_index_data.write_u32(cu_index_entry.loc.unwrap().size.try_into().unwrap())?;
        }
        if has_line {
            cu_index_data.write_u32(cu_index_entry.line.unwrap().size.try_into().unwrap())?;
        }
        if has_str_off {
            cu_index_data.write_u32(cu_index_entry.str_off.unwrap().size.try_into().unwrap())?;
        }
        if has_rng {
            cu_index_data.write_u32(cu_index_entry.rng.unwrap().size.try_into().unwrap())?;
        }
    }

    // FIXME: use the correct alignment here
    let _ = output.obj.append_section_data(output.debug_cu_index, &cu_index_data.into_vec(), 1);
    Ok(())
}

fn main() -> Result<()> {
    let subscriber = Registry::default().with(EnvFilter::from_env("RUST_DWP_LOG")).with(
        HierarchicalLayer::default()
            .with_writer(io::stderr)
            .with_indent_lines(true)
            .with_targets(true)
            .with_indent_amount(2),
    );
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let opt = Opt::from_args();
    trace!(?opt);

    let arena_data = Arena::new();
    let arena_mmap = Arena::new();
    let arena_relocations = Arena::new();

    let obj = load_object_file(&arena_mmap, &opt.executable)?;
    let endianness = runtime_endian_of_object(&obj);
    let (parent_debug_addr, dwarf_objects) =
        parse_executable(&obj, &arena_data, &arena_relocations)?;

    let mut output = create_output_object(obj.architecture(), obj.endianness())?;
    let mut string_table = DwpStringTable::new(endianness);

    let mut cu_index_entries = Vec::new();
    for dwo in dwarf_objects {
        process_dwarf_object(
            parent_debug_addr.clone(),
            dwo,
            &mut cu_index_entries,
            &mut string_table,
            &mut output,
            &arena_data,
            &arena_mmap,
            &arena_relocations,
        )?;
    }

    // Write the merged string table to the `.debug_str.dwo` section.
    let _ = string_table.write(&mut output.obj, output.debug_str);

    write_indices(endianness, cu_index_entries, &mut output)?;

    let mut output_stream = StreamingBuffer::new(BufWriter::new(
        fs::File::create(opt.output).context(DwpError::FailedToCreateOutputFile)?,
    ));
    output.obj.emit(&mut output_stream)?;
    output_stream.result()?;
    output_stream.into_inner().flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::next_pow2;

    #[test]
    fn test_next_pow2() {
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(5), 8);
        assert_eq!(next_pow2(8), 8);
        assert_eq!(next_pow2(13), 16);
        assert_eq!(next_pow2(16), 16);
        assert_eq!(next_pow2(22), 32);
        assert_eq!(next_pow2(30), 32);
        assert_eq!(next_pow2(32), 32);
    }
}
