use anyhow::{Context, Result};
use gimli::RunTimeEndian;
use object::{write::StreamingBuffer, Object};
use std::collections::HashSet;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::{trace, warn};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;
use typed_arena::Arena;

use crate::error::DwpError;
use crate::package::{OutputPackage, PackageFormat};
use crate::util::{load_file_section, load_object_file, parse_executable, Output};

mod error;
mod index;
mod marker;
mod package;
mod relocate;
mod strings;
mod util;

#[derive(Debug, StructOpt)]
#[structopt(name = "rust-dwp", about = "merge split dwarf (.dwo) files")]
struct Opt {
    /// Specify path to input dwarf objects and packages
    #[structopt(parse(from_os_str))]
    inputs: Vec<PathBuf>,
    /// Specify the executable/library files to get the list of *.dwo from
    #[structopt(short = "e", long = "exec", parse(from_os_str))]
    executables: Option<Vec<PathBuf>>,
    /// Specify the path to write the packaged dwp file to
    #[structopt(short = "o", long = "output", parse(from_os_str), default_value = "-")]
    output: PathBuf,
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

    for path in dwarf_object_paths {
        let dwo_obj = match load_object_file(&arena_mmap, &path) {
            Ok(dwo_obj) => dwo_obj,
            Err(e) => {
                warn!(
                    "could not open input dwarf object, dwp may fail later if required unit is \
                     not found: {}",
                    e
                );
                continue;
            }
        };

        let mut load_dwo_section = |id: gimli::SectionId| -> Result<_> {
            load_file_section(id, &dwo_obj, true, &arena_data, &arena_relocations)
        };

        let dwo_dwarf = gimli::Dwarf::load(&mut load_dwo_section)
            .with_context(|| DwpError::LoadInputDwarfObject(path.display().to_string()))?;
        let root_header = match dwo_dwarf.units().next().context(DwpError::ParseUnitHeader)? {
            Some(header) => header,
            None => {
                warn!("input dwarf object has no units, skipping");
                continue;
            }
        };
        let format = PackageFormat::from_dwarf_version(root_header.version());

        if output.is_none() {
            let (format, architecture, endianness) = match output_object_inputs {
                Some(inpts) => inpts,
                None => (format, dwo_obj.architecture(), dwo_obj.endianness()),
            };
            output = Some(OutputPackage::<RunTimeEndian>::new(format, architecture, endianness));
        }

        if let Some(output) = &mut output {
            output
                .append_dwarf_object(
                    &arena_compression,
                    &dwo_obj,
                    &dwo_dwarf,
                    root_header.encoding(),
                    format,
                )
                .with_context(|| DwpError::AddingDwarfObjectToOutput(path.display().to_string()))?;
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
