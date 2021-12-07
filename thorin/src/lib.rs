use std::{
    borrow::Cow,
    collections::HashSet,
    path::{Path, PathBuf},
};

use gimli::RunTimeEndian;
use object::{Architecture, Endianness, FileKind, Object};
use tracing::{debug, trace};

use crate::{
    error::{Error, Result},
    package::{OutputPackage, PackageFormat},
    relocate::RelocationMap,
    util::{load_file_section, load_object_file, parse_executable},
};

mod error;
mod index;
mod marker;
mod package;
mod relocate;
mod strings;
mod util;

/// `Session` is expected to be implemented by users of `thorin`, allowing users of `thorin` to
/// decide how to manage data, rather than `thorin` having arenas internally.
pub trait Session<Relocations> {
    /// Returns a reference to `data`'s contents with lifetime `'session`.
    fn alloc_data<'session>(&'session self, data: Vec<u8>) -> &'session [u8];

    /// Returns a reference to `data`'s contents with lifetime `'input`.
    ///
    /// If `Cow` is borrowed, then return the contained reference (`'input`). If `Cow` is owned,
    /// then calls `alloc_data` to return a reference of lifetime `'session`, which is guaranteed
    /// to be longer than `'input`, so can be returned.
    fn alloc_owned_cow<'input, 'session: 'input>(
        &'session self,
        data: Cow<'input, [u8]>,
    ) -> &'input [u8] {
        match data {
            Cow::Borrowed(data) => data,
            Cow::Owned(data) => self.alloc_data(data),
        }
    }

    /// Returns a reference to `relocation` with lifetime `'session`.
    fn alloc_relocation<'session>(&'session self, data: Relocations) -> &'session Relocations;

    /// Returns a reference to contents of file at `path` with lifetime `'session`.
    fn read_input<'session>(&'session self, path: &Path) -> std::io::Result<&'session [u8]>;
}

/// Process an input file - adding it to an output package.
///
/// Will use the package format, architecture and endianness from the file to create the output
/// package if it does not already exist (and may use the provided format, architecture and
/// endianness).
#[tracing::instrument(level = "trace", skip(sess, obj, output))]
fn process_input_file<'input, 'session: 'input>(
    sess: &'session impl Session<RelocationMap>,
    path: &str,
    obj: &'input object::File<'input>,
    output_object_inputs: &mut Option<(PackageFormat, Architecture, Endianness)>,
    output: &mut Option<OutputPackage<'_, RunTimeEndian>>,
) -> Result<()> {
    let mut load_dwo_section =
        |id: gimli::SectionId| -> Result<_> { load_file_section(sess, id, &obj, true) };

    let dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
    let root_header = match dwarf.units().next().map_err(Error::ParseUnitHeader)? {
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
        output.append_dwarf_object(sess, obj, &dwarf, root_header.encoding(), format)?;
    }

    Ok(())
}

/// Create a DWARF package from the files in `inputs`, ensuring that all DWARF objects referenced
/// by `executables` are found, writing the final DWARF package to `output_path`.
pub fn package<'session>(
    sess: &'session impl Session<RelocationMap>,
    inputs: Vec<PathBuf>,
    executables: Option<Vec<PathBuf>>,
) -> Result<object::write::Object> {
    let mut output_object_inputs = None;

    // Paths to DWARF objects to open (from positional arguments or referenced by executables).
    let mut dwarf_object_paths = inputs;
    // `DwoId`s or `DebugTypeSignature`s referenced by any executables that have been opened,
    // must find.
    let mut target_dwarf_objects = HashSet::new();

    if let Some(executables) = executables {
        for executable in executables {
            let obj = load_object_file(sess, &executable)?;
            let found_output_object_inputs =
                parse_executable(sess, &obj, &mut target_dwarf_objects, &mut dwarf_object_paths)?;

            output_object_inputs = output_object_inputs.or(found_output_object_inputs);
        }
    }

    // Need to know the package format, architecture and endianness to create the output object.
    // Retrieve these from the input files - either the executable or the dwarf objects - so delay
    // creation until these inputs are definitely available.
    let mut output = None;

    for path in &dwarf_object_paths {
        let data = match sess.read_input(&path) {
            Ok(data) => data,
            Err(e) => {
                debug!(
                    ?path,
                    "could not open, may fail if this file contains units referenced by \
                     executable that are not otherwise found.",
                );
                trace!(?e);
                continue;
            }
        };

        match FileKind::parse(data).map_err(Error::ParseFileKind)? {
            FileKind::Archive => {
                let archive = object::read::archive::ArchiveFile::parse(data)
                    .map_err(|e| Error::ParseArchiveFile(e, path.display().to_string()))?;

                for member in archive.members() {
                    let member = member.map_err(Error::ParseArchiveMember)?;
                    let data = member.data(data)?;
                    if matches!(
                        FileKind::parse(data).map_err(Error::ParseFileKind)?,
                        FileKind::Elf32 | FileKind::Elf64
                    ) {
                        let name = path.display().to_string()
                            + ":"
                            + &String::from_utf8_lossy(member.name());
                        let obj = object::File::parse(data)
                            .map_err(|e| Error::ParseObjectFile(e, name.clone()))?;
                        process_input_file(
                            sess,
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
                    .map_err(|e| Error::ParseObjectFile(e, path.display().to_string()))?;
                process_input_file(
                    sess,
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

    match output {
        Some(output) => {
            output.verify(&target_dwarf_objects)?;
            output.finish()
        }
        None => Err(Error::NoOutputObjectCreated),
    }
}
