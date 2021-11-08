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

#[derive(Debug, Error)]
enum DwpError {
    #[error("compilation unit with dwo id has no dwo name")]
    DwoIdWithoutDwoName,
    #[error("compilation unit with dwo id doesn't normalize to dwo id")]
    DwoIdAttributeNormalizeWrong,
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
    arena_mmap: &'arena Arena<memmap::Mmap>,
    path: &'input Path,
) -> Result<object::File<'arena>> {
    let file = fs::File::open(&path)
        .with_context(|| format!("failed to open object file at {}", path.display()))?;

    let mmap = (unsafe { memmap::Mmap::map(&file) })
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
fn load_file_section<'input, 'arena>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    is_dwo: bool,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
) -> Result<gimli::EndianSlice<'arena, gimli::RunTimeEndian>> {
    let name = if is_dwo {
        id.dwo_name()
    } else {
        Some(id.name())
    };

    let data = match name.and_then(|name| file.section_by_name(&name)) {
        Some(ref section) => section.uncompressed_data()?,
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };
    let data_ref = (*arena_data.alloc(data)).borrow();
    Ok(gimli::EndianSlice::new(
        data_ref,
        runtime_endian_of_object(file),
    ))
}

/// Returns the `DwoId` of a DIE.
///
/// With DWARF 5, `DwoId` is in the unit header of a skeleton unit (identifying the split
/// compilation unit that contains the debuginfo) or split compilation unit (identifying the
/// skeleton unit that this debuginfo corresponds to). In earlier DWARF versions with GNU extension,
/// `DW_AT_GNU_dwo_id` attribute of the DIE contains the `DwoId`.
fn dwo_id_of_die<R: gimli::Reader>(
    unit: &gimli::Unit<R>,
    die: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<Option<gimli::DwoId>> {
    match unit.header.type_() {
        // DWARF 5
        gimli::UnitType::Skeleton(dwo_id) | gimli::UnitType::SplitCompilation(dwo_id) => {
            Ok(Some(dwo_id))
        }
        // GNU Extension (maybe!)
        gimli::UnitType::Compilation => match die.attr_value(gimli::DW_AT_GNU_dwo_id)? {
            Some(gimli::AttributeValue::DwoId(dwo_id)) => Ok(Some(dwo_id)),
            // If there isn't a `DwoId` then this isn't a relevant compilation unit to dwp.
            None => return Ok(None),
            // If there is a `DW_AT_GNU_dwo_id` that doesn't normalize to a `DwoId`.
            _ => return Err(anyhow!(DwpError::DwoIdAttributeNormalizeWrong)),
        },
        // Wrong compilation unit type.
        _ => Ok(None),
    }
}

/// Returns the `DwoId` and `PathBuf` of a DIE.
///
/// See `dwo_id_of_die` for detailed description of `DwoId` source. With DWARF 5, skeleton
/// compilation unit will contain a `DW_AT_dwo_name` attribute with the name of the dwarf object
/// file containing the split compilation unit with the `DwoId`. In earlier DWARF
/// versions with GNU extension, `DW_AT_GNU_dwo_name` attribute contains name.
fn dwo_id_and_path_of_die<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    die: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Result<Option<(gimli::DwoId, PathBuf)>> {
    let dwo_id = if let Some(dwo_id) = dwo_id_of_die(unit, die)? {
        dwo_id
    } else {
        return Ok(None);
    };

    let dwo_name = if let Some(val) = die.attr_value(gimli::DW_AT_dwo_name)? {
        // DWARF 5
        val
    } else if let Some(val) = die.attr_value(gimli::DW_AT_GNU_dwo_name)? {
        // GNU Extension
        val
    } else {
        return Err(anyhow!(DwpError::DwoIdWithoutDwoName));
    };
    let dwo_name = dwarf
        .attr_string(&unit, dwo_name)?
        .to_string()?
        .into_owned();

    // Prepend the compilation directory if it exists.
    let mut dwo_path = if let Some(comp_dir) = &unit.comp_dir {
        PathBuf::from(comp_dir.to_string()?.into_owned())
    } else {
        PathBuf::new()
    };
    dwo_path.push(dwo_name);

    Ok(Some((dwo_id, dwo_path)))
}

/// Helper enum returned by the operation passed to `with_each_die` so that the closure can
/// manage the control flow of the loop in the calling function.
enum WithEachControlFlow {
    /// `continue`
    Continue,
    /// `break`
    #[allow(dead_code)]
    Break,
}

/// Iterate over each debug information entry in an object, invoking a closure to perform an
/// operation on each.
fn with_each_die<Reader, Op>(dwarf: &gimli::Dwarf<Reader>, mut op: Op) -> Result<()>
where
    Reader: gimli::Reader,
    Op: FnMut(
        &gimli::Dwarf<Reader>,
        &gimli::Unit<Reader>,
        &gimli::DebuggingInformationEntry<Reader>,
    ) -> Result<WithEachControlFlow>,
{
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        let abbreviations = dwarf.abbreviations(&unit.header)?;
        let mut entry_cursor = unit.header.entries(&abbreviations);
        while let Some((_, die)) = entry_cursor.next_dfs()? {
            match op(&dwarf, &unit, &die)? {
                WithEachControlFlow::Continue => continue,
                WithEachControlFlow::Break => break,
            }
        }
    }
    Ok(())
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
    let mut load_section =
        |id: gimli::SectionId| -> Result<_, _> { load_file_section(id, &obj, false, &arena_data) };

    let mut dwos = Vec::new();

    {
        let _guard = span!(Level::TRACE, "read dwarf objects from executable");
        let exec_dwarf = gimli::Dwarf::load(&mut load_section)?;
        with_each_die(&exec_dwarf, |dwarf, unit, die| {
            if die.tag() != gimli::DW_TAG_compile_unit {
                return Ok(WithEachControlFlow::Continue);
            }

            if let Some((dwo_id, path)) = dwo_id_and_path_of_die(&dwarf, &unit, &die)? {
                println!("dwo id: {:#x}, dwo path: {:?}", dwo_id.0, path);
                dwos.push((dwo_id, path));
            }

            Ok(WithEachControlFlow::Continue)
        })?;
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
            load_file_section(id, &dwo_obj, true, &arena_data)
        };

        let dwo_dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
        with_each_die(&dwo_dwarf, |_dwarf, unit, die| {
            if die.tag() != gimli::DW_TAG_compile_unit {
                return Ok(WithEachControlFlow::Continue);
            }

            if let Some(dwo_id) = dwo_id_of_die(&unit, &die)? {
                if target_dwo_id == dwo_id {
                    println!("found dwo id: {:#x}", dwo_id.0);
                }
            }

            Ok(WithEachControlFlow::Continue)
        })?;
    }

    Ok(())
}
