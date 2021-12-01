use anyhow::{Context, Result};
use gimli::RunTimeEndian;
use object::{write::StreamingBuffer, Architecture, Endianness, FileKind, Object};
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::{debug, trace, warn};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;
use typed_arena::Arena;

use crate::error::DwpError;
use crate::package::{OutputPackage, PackageFormat};
use crate::relocate::RelocationMap;
use crate::util::{
    load_file_section, load_object_file, open_and_mmap_input, parse_executable, Output,
};

mod error;
mod index;
mod marker;
mod package;
mod relocate;
mod strings;
mod util;

#[derive(Debug, StructOpt)]
#[structopt(name = "rust-dwp", about = "merge dwarf objects into dwarf packages")]
struct Opt {
    /// Specify path to input dwarf objects and packages
    #[structopt(parse(from_os_str))]
    inputs: Vec<PathBuf>,
    /// Specify path to executables to read list of dwarf objects from
    #[structopt(short = "e", long = "exec", parse(from_os_str))]
    executables: Option<Vec<PathBuf>>,
    /// Specify path to write the dwarf package to
    #[structopt(short = "o", long = "output", parse(from_os_str), default_value = "-")]
    output: PathBuf,
}

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
    output: &mut Option<OutputPackage<RunTimeEndian>>,
) -> Result<()> {
    let mut load_dwo_section = |id: gimli::SectionId| -> Result<_> {
        load_file_section(id, &obj, true, &arena_data, &arena_relocations)
    };

    let dwarf = gimli::Dwarf::load(&mut load_dwo_section)
        .with_context(|| DwpError::LoadInputDwarfObject(String::from(path)))?;
    let root_header = match dwarf.units().next().context(DwpError::ParseUnitHeader)? {
        Some(header) => header,
        None => {
            warn!("input dwarf object has no units, skipping");
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
        output
            .append_dwarf_object(&arena_compression, &obj, &dwarf, root_header.encoding(), format)
            .with_context(|| DwpError::AddingDwarfObjectToOutput(String::from(path)))?;
    }

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
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");

    let opt = Opt::from_args();
    trace!(?opt);

    let arena_compression = Arena::new();
    let arena_data = Arena::new();
    let arena_mmap = Arena::new();
    let arena_relocations = Arena::new();

    let mut output_object_inputs = None;

    // Paths to DWARF objects to open (from positional arguments or referenced by executables).
    let mut dwarf_object_paths = opt.inputs;
    // `DwoId`s or `DebugTypeSignature`s referenced by any executables that have been opened,
    // must find.
    let mut target_dwarf_objects = HashSet::new();

    if let Some(executables) = opt.executables {
        for executable in &executables {
            let obj = load_object_file(&arena_mmap, executable)
                .with_context(|| DwpError::LoadingExecutable(executable.display().to_string()))?;
            let found_output_object_inputs = parse_executable(
                &arena_data,
                &arena_relocations,
                &obj,
                &mut target_dwarf_objects,
                &mut dwarf_object_paths,
            )
            .with_context(|| {
                DwpError::FindingDwarfObjectsInExecutable(executable.display().to_string())
            })?;

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
                warn!(
                    "Could not open `{}`! May fail if this file contains units referenced by \
                     executable that are not otherwise found. {:?}",
                    path.to_string_lossy(),
                    e,
                );
                continue;
            }
        };

        match FileKind::parse(data).context(DwpError::ParseFileKind)? {
            FileKind::Archive => {
                let archive = object::read::archive::ArchiveFile::parse(data)
                    .context(DwpError::ParseArchiveFile)?;

                for member in archive.members() {
                    let member = member.context(DwpError::ParseArchiveMember)?;
                    let data = member.data(data)?;
                    if matches!(
                        FileKind::parse(data).context(DwpError::ParseFileKind)?,
                        FileKind::Elf32 | FileKind::Elf64
                    ) {
                        let name = path.display().to_string()
                            + ":"
                            + &String::from_utf8_lossy(member.name());
                        let obj = object::File::parse(data).context(DwpError::ParseObjectFile)?;
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
                let obj = object::File::parse(data).context(DwpError::ParseObjectFile)?;
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
                warn!(
                    "Input file `{}` is not an archive or elf object, skipping...",
                    path.to_string_lossy()
                );
            }
        }
    }

    if let Some(output) = output {
        output.verify(&target_dwarf_objects)?;

        let output_stream = Output::new(opt.output.as_ref())
            .with_context(|| DwpError::CreateOutputFile(opt.output.display().to_string()))?;
        let mut output_stream = StreamingBuffer::new(BufWriter::new(output_stream));
        output.emit(&mut output_stream).context(DwpError::WriteInMemoryRepresentation)?;
        output_stream.result().context(DwpError::WriteBuffer)?;
        output_stream.into_inner().flush().context(DwpError::FlushBufferedWriter)?;
    }

    Ok(())
}
