use gimli::RunTimeEndian;
use object::{write::StreamingBuffer, Architecture, Endianness, FileKind, Object};
use std::{
    borrow::Cow,
    collections::HashSet,
    io::{BufWriter, Write},
    path::PathBuf,
};
use tracing::{debug, trace};
use typed_arena::Arena;

use crate::{
    error::Result,
    package::{OutputPackage, PackageFormat},
    relocate::RelocationMap,
    util::{load_file_section, load_object_file, open_and_mmap_input, parse_executable, Output},
};

pub use crate::error::DwpError;

mod error;
mod index;
mod marker;
mod package;
mod relocate;
mod strings;
mod util;

/// Process an input file - adding it to an output package.
///
/// Will use the package format, architecture and endianness from the file to create the output
/// package if it does not already exist (and may use the provided format, architecture and
/// endianness).
#[tracing::instrument(
    level = "trace",
    skip(arena_compression, arena_data, arena_relocations, obj, output)
)]
fn process_input_file<'input, 'arena: 'input>(
    arena_compression: &'arena Arena<Vec<u8>>,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
    path: &str,
    obj: &object::File<'input>,
    output_object_inputs: &mut Option<(PackageFormat, Architecture, Endianness)>,
    output: &mut Option<OutputPackage<'_, RunTimeEndian>>,
) -> Result<()> {
    let mut load_dwo_section = |id: gimli::SectionId| -> Result<_> {
        load_file_section(id, &obj, true, &arena_data, &arena_relocations)
    };

    let dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
    let root_header = match dwarf.units().next().map_err(DwpError::ParseUnitHeader)? {
        Some(header) => header,
        None => {
            debug!("input dwarf object has no units, skipping");
            return Ok(());
        }
    };
    let format = PackageFormat::from_dwarf_version(root_header.version());

    if output.is_none() {
        let (format, architecture, endianness) = match *output_object_inputs {
            Some(inpts) => inpts,
            None => (format, obj.architecture(), obj.endianness()),
        };

        *output = Some(OutputPackage::<RunTimeEndian>::new(format, architecture, endianness));
    }

    if let Some(output) = output {
        output.append_dwarf_object(
            &arena_compression,
            &obj,
            &dwarf,
            root_header.encoding(),
            format,
        )?;
    }

    Ok(())
}

/// Create a DWARF package from the files in `inputs`, ensuring that all DWARF objects referenced
/// by `executables` are found, writing the final DWARF package to `output_path`.
pub fn package(
    inputs: Vec<PathBuf>,
    executables: Option<Vec<PathBuf>>,
    output_path: PathBuf,
) -> Result<()> {
    let arena_compression = Arena::new();
    let arena_data = Arena::new();
    let arena_mmap = Arena::new();
    let arena_relocations = Arena::new();

    let mut output_object_inputs = None;

    // Paths to DWARF objects to open (from positional arguments or referenced by executables).
    let mut dwarf_object_paths = inputs;
    // `DwoId`s or `DebugTypeSignature`s referenced by any executables that have been opened,
    // must find.
    let mut target_dwarf_objects = HashSet::new();

    if let Some(executables) = executables {
        for executable in executables {
            let obj = load_object_file(&arena_mmap, &executable)?;
            let found_output_object_inputs = parse_executable(
                &arena_data,
                &arena_relocations,
                &obj,
                &mut target_dwarf_objects,
                &mut dwarf_object_paths,
            )?;

            output_object_inputs = output_object_inputs.or(found_output_object_inputs);
        }
    }

    // Need to know the package format, architecture and endianness to create the output object.
    // Retrieve these from the input files - either the executable or the dwarf objects - so delay
    // creation until these inputs are definitely available.
    let mut output = None;

    for path in &dwarf_object_paths {
        let data = match open_and_mmap_input(&arena_mmap, &path) {
            Ok(data) => data,
            Err(e) => {
                debug!(
                    ?path,
                    "could not open,m ay fail if this file contains units referenced by \
                     executable that are not otherwise found.",
                );
                trace!(?e);
                continue;
            }
        };

        match FileKind::parse(data).map_err(DwpError::ParseFileKind)? {
            FileKind::Archive => {
                let archive = object::read::archive::ArchiveFile::parse(data)
                    .map_err(|e| DwpError::ParseArchiveFile(e, path.display().to_string()))?;

                for member in archive.members() {
                    let member = member.map_err(DwpError::ParseArchiveMember)?;
                    let data = member.data(data)?;
                    if matches!(
                        FileKind::parse(data).map_err(DwpError::ParseFileKind)?,
                        FileKind::Elf32 | FileKind::Elf64
                    ) {
                        let name = path.display().to_string()
                            + ":"
                            + &String::from_utf8_lossy(member.name());
                        let obj = object::File::parse(data)
                            .map_err(|e| DwpError::ParseObjectFile(e, name.clone()))?;
                        process_input_file(
                            &arena_compression,
                            &arena_data,
                            &arena_relocations,
                            &name,
                            &obj,
                            &mut output_object_inputs,
                            &mut output,
                        )?;
                    } else {
                        debug!("skipping non-elf file in archive input");
                    }
                }
            }
            FileKind::Elf32 | FileKind::Elf64 => {
                let obj = object::File::parse(data)
                    .map_err(|e| DwpError::ParseObjectFile(e, path.display().to_string()))?;
                process_input_file(
                    &arena_compression,
                    &arena_data,
                    &arena_relocations,
                    &path.to_string_lossy(),
                    &obj,
                    &mut output_object_inputs,
                    &mut output,
                )?;
            }
            _ => {
                debug!(?path, "input file is not an archive or elf object, skipping...",);
            }
        }
    }

    if let Some(output) = output {
        output.verify(&target_dwarf_objects)?;

        let output_stream = Output::new(output_path.as_ref())
            .map_err(|e| DwpError::CreateOutputFile(e, output_path.display().to_string()))?;
        let mut output_stream = StreamingBuffer::new(BufWriter::new(output_stream));
        output.emit(&mut output_stream)?;
        output_stream.result().map_err(DwpError::WriteBuffer)?;
        output_stream.into_inner().flush().map_err(DwpError::FlushBufferedWriter)?;
    }

    Ok(())
}
