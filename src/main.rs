use crate::relocate::{add_relocations, Relocate, RelocationMap};
use anyhow::{anyhow, Context, Result};
use object::{Object, ObjectSection};
use std::borrow::{Borrow, Cow};
use std::fs;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use thiserror::Error;
use tracing::{span, trace, Level};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
use typed_arena::Arena;

mod relocate;

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
}

#[derive(Debug, StructOpt)]
#[structopt(name = "rust-dwp", about = "merge split dwarf (.dwo) files")]
struct Opt {
    /// Specify the executable/library files to get the list of *.dwo from
    #[structopt(short = "e", long = "exec", parse(from_os_str))]
    executable: PathBuf,
}

/// Load and parse an object file.
#[tracing::instrument(level = "trace", skip(arena_mmap))]
fn load_object_file<'input, 'arena>(
    arena_mmap: &'arena Arena<memmap2::Mmap>,
    path: &'input Path,
) -> Result<object::File<'arena>> {
    let file = fs::File::open(&path)
        .with_context(|| format!("failed to open object file at {}", path.display()))?;

    let mmap = (unsafe { memmap2::Mmap::map(&file) })
        .with_context(|| format!("failed to map file at {}", path.display()))?;

    let mmap_ref = (*arena_mmap.alloc(mmap)).borrow();
    object::File::parse(&**mmap_ref)
        .with_context(|| format!("failed to parse file at {}", path.display()))
}

/// Returns the `RunTimeEndian` which matches the endianness of the object file.
fn runtime_endian_of_object<'a>(obj: &object::File<'a>) -> gimli::RunTimeEndian {
    if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    }
}

/// Loads a section of a file from `object::File` into a `gimli::EndianSlice`. Expected to be
/// curried using a closure and provided to `Dwarf::load`.
#[tracing::instrument(level = "trace", skip(file, arena_data, arena_relocations))]
fn load_file_section<'input, 'arena>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    is_dwo: bool,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<Relocate<'arena, gimli::EndianSlice<'arena, gimli::RunTimeEndian>>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo {
        id.dwo_name()
    } else {
        Some(id.name())
    };

    let data = match name.and_then(|name| file.section_by_name(&name)) {
        Some(ref section) => {
            if !is_dwo {
                add_relocations(&mut relocations, file, section)?;
            }
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };

    let data_ref = (*arena_data.alloc(data)).borrow();
    let reader = gimli::EndianSlice::new(data_ref, runtime_endian_of_object(file));
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
fn dwo_id_of_unit<R: gimli::Reader>(unit: &gimli::Unit<R>) -> Option<gimli::DwoId> {
    match unit.header.type_() {
        // DWARF 5
        gimli::UnitType::Skeleton(dwo_id) | gimli::UnitType::SplitCompilation(dwo_id) => {
            Some(dwo_id)
        }
        // GNU Extension (maybe!)
        gimli::UnitType::Compilation => unit.dwo_id,
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
fn dwo_id_and_path_of_unit<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
) -> Result<Option<(gimli::DwoId, PathBuf)>> {
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
    let mut dwo_path = if let Some(comp_dir) = &unit.comp_dir {
        PathBuf::from(comp_dir.to_string()?.into_owned())
    } else {
        PathBuf::new()
    };
    dwo_path.push(dwo_name);

    Ok(Some((dwo_id, dwo_path)))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_env_filter(EnvFilter::from_env("RUST_DWP_LOG"))
        .init();

    let opt = Opt::from_args();
    trace!(?opt);

    let arena_mmap = Arena::new();
    let obj = load_object_file(&arena_mmap, &opt.executable)?;

    let arena_data = Arena::new();
    let arena_relocations = Arena::new();
    let mut load_section = |id: gimli::SectionId| -> Result<_, _> {
        load_file_section(id, &obj, false, &arena_data, &arena_relocations)
    };

    let mut dwos = Vec::new();

    {
        let _guard = span!(Level::TRACE, "read dwarf objects from executable");
        let exec_dwarf = gimli::Dwarf::load(&mut load_section)?;
        let mut iter = exec_dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = exec_dwarf.unit(header)?;

            if let Some((dwo_id, path)) = dwo_id_and_path_of_unit(&exec_dwarf, &unit)? {
                println!("dwo id: {:#x}, dwo path: {:?}", dwo_id.0, path);
                dwos.push((dwo_id, path));
            }
        }
    }

    for (target_dwo_id, path) in dwos {
        let _guard = span!(
            Level::TRACE,
            "find compilation unit in dwarf object",
            dwo_id = target_dwo_id.0,
            path = path.to_str().unwrap()
        );
        let dwo_obj = load_object_file(&arena_mmap, &path)?;
        let mut load_dwo_section = |id: gimli::SectionId| -> Result<_, _> {
            load_file_section(id, &dwo_obj, true, &arena_data, &arena_relocations)
        };

        let dwo_dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
        let mut iter = dwo_dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwo_dwarf.unit(header)?;

            if let Some(dwo_id) = dwo_id_of_unit(&unit) {
                if target_dwo_id == dwo_id {
                    println!("found dwo id: {:#x}", dwo_id.0);
                }
            }
        }
    }

    Ok(())
}
