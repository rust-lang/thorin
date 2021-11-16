use crate::relocate::{add_relocations, Relocate, RelocationMap};
use anyhow::{anyhow, Context, Result};
use gimli::{
    write::{EndianVec, Writer},
    DebugAddr, DebugStrOffset, DebugStrOffsetsBase, DebugStrOffsetsIndex, DwarfFileType, DwoId,
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
    fn new(endianity: E) -> Self {
        Self {
            debug_str: gimli::write::DebugStr(EndianVec::new(endianity)),
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
            return Ok(*self
                .offsets
                .get(&index)
                .expect("insert exists but no offset"));
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
        obj.append_section_data(section, &self.debug_str.0.into_vec(), 1)
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
    let name = if is_dwo {
        id.dwo_name()
    } else {
        Some(id.name())
    };

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
    Ok(Relocate {
        relocations,
        section,
        reader,
    })
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
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => Some(dwo_id),
        // GNU Extension (maybe!)
        UnitType::Compilation => unit.dwo_id,
        // Wrong compilation unit type.
        _ => None,
    }
}

/// Returns the `DwoId` and `PathBuf` of a DIE.
///
/// See `dwo_id_of_die` for detailed description of `DwoId` source. With DWARF 5, skeleton
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

        dwarf
            .attr_string(&unit, dwo_name)?
            .to_string()?
            .into_owned()
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

    Ok(DwpOutputObject {
        obj,
        debug_abbrev,
        debug_line,
        debug_loclists,
        debug_rnglists,
        debug_str,
        debug_str_offsets,
    })
}

/// Read the string offsets from `.debug_str_offsets.dwo` in the DWARF object, adding each to the
/// in-progress `.debug_str` (`DwpStringTable`) and building a new `.debug_str_offsets.dwo` to be
/// the current DWARF object's contribution to the DWARF package.
#[tracing::instrument(level = "trace", skip(dwo_obj, dwo_dwarf, string_table, output))]
fn append_debug_str_offset<'input, 'output, 'arena: 'input, Endian: gimli::Endianity>(
    dwo_obj: &object::File<'input>,
    dwo_dwarf: &gimli::Dwarf<DwpReader<'arena>>,
    string_table: &mut DwpStringTable<Endian>,
    output: &mut DwpOutputObject<'output>,
) -> Result<u64> {
    let mut data = EndianVec::new(runtime_endian_of_object(dwo_obj));

    let root_header = dwo_dwarf
        .units()
        .next()?
        .context(DwpError::DwarfObjectWithNoUnits)?;
    let encoding = root_header.encoding();
    let base = DebugStrOffsetsBase::default_for_encoding_and_file(encoding, DwarfFileType::Dwo);

    let section_name = gimli::SectionId::DebugStrOffsets.dwo_name().unwrap();
    let section = dwo_obj
        .section_by_name(section_name)
        .with_context(|| DwpError::DwarfObjectMissingSection(section_name.to_string()))?;
    let section_size = section.size();

    let entry_size = match encoding.format {
        Format::Dwarf32 => 4,
        Format::Dwarf64 => 8,
    };

    debug!(
        ?section_size,
        str_offset_size_num_elements = section_size / entry_size
    );
    for i in 0..(section_size / entry_size) {
        let dwo_index = DebugStrOffsetsIndex(i as usize);
        let dwo_offset =
            dwo_dwarf
                .debug_str_offsets
                .get_str_offset(encoding.format, base, dwo_index)?;
        let dwo_str = dwo_dwarf.debug_str.get_str(dwo_offset)?;
        let dwo_str = dwo_str.to_string()?;

        let dwp_offset = string_table.get_or_insert(dwo_str.as_ref())?;
        debug!(
            ?i,
            ?dwo_str,
            "dwo_offset={:#x} dwp_offset={:#x}",
            dwo_offset.0,
            dwp_offset.0
        );

        match encoding.format {
            Format::Dwarf32 => {
                data.write_u32(
                    dwp_offset
                        .0
                        .try_into()
                        .context(DwpError::DwpStrOffsetOutOfRange)?,
                )?;
            }
            Format::Dwarf64 => {
                data.write_u64(
                    dwp_offset
                        .0
                        .try_into()
                        .context(DwpError::DwpStrOffsetOutOfRange)?,
                )?;
            }
        }
    }

    Ok(output
        .obj
        .append_section_data(output.debug_str_offsets, &data.into_vec(), section.align()))
}

/// Process a DWARF object. Copies relevant sections, compilation/type units and strings from DWARF
/// object into output object.
#[tracing::instrument(
    level = "trace",
    skip(
        parent_debug_addr,
        string_table,
        output,
        arena_data,
        arena_mmap,
        arena_relocations
    )
)]
fn process_dwarf_object<'input, 'output, 'arena: 'input, Endian: gimli::Endianity>(
    parent_debug_addr: DebugAddr<DwpReader<'arena>>,
    dwo: TargetDwarfObject,
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

    let mut append_from_to = |from_id: gimli::SectionId, to_id: SectionId| -> Result<u64> {
        let name = from_id.dwo_name().unwrap();
        let section = dwo_obj
            .section_by_name(name)
            .with_context(|| DwpError::DwarfObjectMissingSection(name.to_string()))?;
        Ok(output
            .obj
            .append_section_data(to_id, section.data()?, section.align()))
    };

    let _ = append_from_to(gimli::SectionId::DebugAbbrev, output.debug_abbrev);
    let _ = append_from_to(gimli::SectionId::DebugLine, output.debug_line);
    let _ = append_from_to(gimli::SectionId::DebugLocLists, output.debug_loclists);
    let _ = append_from_to(gimli::SectionId::DebugRngLists, output.debug_rnglists);

    let _ = append_debug_str_offset(&dwo_obj, &dwo_dwarf, string_table, output)?;

    Ok(())
}

fn main() -> Result<()> {
    let subscriber = Registry::default()
        .with(EnvFilter::from_env("RUST_DWP_LOG"))
        .with(
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
    let (parent_debug_addr, dwarf_objects) =
        parse_executable(&obj, &arena_data, &arena_relocations)?;

    let mut output = create_output_object(obj.architecture(), obj.endianness())?;
    let mut string_table = DwpStringTable::new(runtime_endian_of_object(&obj));

    for dwo in dwarf_objects {
        process_dwarf_object(
            parent_debug_addr.clone(),
            dwo,
            &mut string_table,
            &mut output,
            &arena_data,
            &arena_mmap,
            &arena_relocations,
        )?;
    }

    // Write the merged string table to the `.debug_str.dwo` section.
    let _ = string_table.write(&mut output.obj, output.debug_str);

    let mut output_stream = StreamingBuffer::new(BufWriter::new(
        fs::File::create(opt.output).context(DwpError::FailedToCreateOutputFile)?,
    ));
    output.obj.emit(&mut output_stream)?;
    output_stream.result()?;
    output_stream.into_inner().flush()?;

    Ok(())
}
