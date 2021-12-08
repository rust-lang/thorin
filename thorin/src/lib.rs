use std::{
    borrow::Cow,
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};

use gimli::{EndianSlice, Reader};
use object::{
    write::Object as WritableObject, Architecture, Endianness, FileKind, Object, ObjectSection,
};
use tracing::{debug, trace};

use crate::{
    error::Result,
    index::Bucketable,
    package::{DwarfObjectIdentifier, InProgressDwarfPackage, PackageFormat},
    relocate::{add_relocations, DwpReader, Relocate, RelocationMap},
    util::{dwo_identifier_of_unit, runtime_endian_from_endianness},
};

mod error;
mod index;
mod marker;
mod package;
mod relocate;
mod strings;
mod util;

pub use crate::error::Error;

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

/// Loads a section of a file from `object::File` into a `gimli::EndianSlice`. Expected to be
/// curried using a closure and provided to `Dwarf::load`.
#[tracing::instrument(level = "trace", skip(sess, obj))]
fn load_file_section<'input, 'session: 'input>(
    sess: &'session impl Session<RelocationMap>,
    id: gimli::SectionId,
    obj: &object::File<'input>,
    is_dwo: bool,
) -> Result<DwpReader<'input>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo { id.dwo_name() } else { Some(id.name()) };

    let data = match name.and_then(|name| obj.section_by_name(&name)) {
        Some(ref section) => {
            if !is_dwo {
                add_relocations(&mut relocations, obj, section)?;
            }
            section.compressed_data()?.decompress()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };

    let data_ref = sess.alloc_owned_cow(data);
    let reader = EndianSlice::new(data_ref, runtime_endian_from_endianness(obj.endianness()));
    let section = reader;
    let relocations = sess.alloc_relocation(relocations);
    Ok(Relocate { relocations, section, reader })
}

/// Should missing DWARF objects referenced by executables be skipped or result in an error?
///
/// Referenced objects that are still missing when the DWARF package is finished will result in
/// an error.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum MissingReferencedObjectBehaviour {
    /// Skip missing referenced DWARF objects - useful if this is expected, i.e. the path in the
    /// executable is wrong, but the referenced object will be found because it is an input.
    Skip,
    /// Error when encountering missing referenced DWARF objects.
    Error,
}

impl MissingReferencedObjectBehaviour {
    /// Should missing referenced objects be skipped?
    pub fn skip_missing(&self) -> bool {
        match *self {
            MissingReferencedObjectBehaviour::Skip => true,
            MissingReferencedObjectBehaviour::Error => false,
        }
    }
}

/// Builder for DWARF packages, add input objects/packages with `add_input_object` or input objects
/// referenced by an executable with `add_executable` before accessing the completed object with
/// `finish`.
pub struct DwarfPackage<'output, 'session: 'output, Sess: Session<RelocationMap>> {
    sess: &'session Sess,
    maybe_in_progress: Option<InProgressDwarfPackage<'output>>,
    targets: HashSet<DwarfObjectIdentifier>,
}

impl<'output, 'session: 'output, Sess> fmt::Debug for DwarfPackage<'output, 'session, Sess>
where
    Sess: Session<RelocationMap>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DwarfPackage")
            .field("in_progress", &self.maybe_in_progress)
            .field("target_count", &self.targets.len())
            .finish()
    }
}

impl<'output, 'session: 'output, Sess> DwarfPackage<'output, 'session, Sess>
where
    Sess: Session<RelocationMap>,
{
    /// Create a new `DwarfPackage` with the provided `Session` implementation.
    pub fn new(sess: &'session Sess) -> Self {
        Self { sess, maybe_in_progress: None, targets: HashSet::new() }
    }

    /// Creating a `InProgressDwarfPackage` requires knowing the format of the package being
    /// created, its architecture and its endianness - these aren't known when a `DwarfPackage` is
    /// created, so use this function to access the package, creating it if it hasn't been created
    /// yet.
    fn in_progress_package(
        &mut self,
        format: PackageFormat,
        architecture: Architecture,
        endianness: Endianness,
    ) -> &mut InProgressDwarfPackage<'output> {
        if self.maybe_in_progress.is_none() {
            self.maybe_in_progress =
                Some(InProgressDwarfPackage::new(format, architecture, endianness));
        }

        // EXPECT: in-progress package already exists or was just created
        self.maybe_in_progress.as_mut().expect("`DwarfPackage::package` is broken")
    }

    /// Add an input object to the in-progress package.
    #[tracing::instrument(level = "trace", skip(obj))]
    fn process_input_object<'input>(&mut self, obj: &'input object::File<'input>) -> Result<()> {
        let mut load_dwo_section =
            |id: gimli::SectionId| -> Result<_> { load_file_section(self.sess, id, &obj, true) };

        let dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
        let root_header = match dwarf.units().next().map_err(Error::ParseUnitHeader)? {
            Some(header) => header,
            None => {
                debug!("input dwarf object has no units, skipping");
                return Ok(());
            }
        };
        let format = PackageFormat::from_dwarf_version(root_header.version());

        let sess = self.sess;
        self.in_progress_package(format, obj.architecture(), obj.endianness()).append_dwarf_object(
            sess,
            obj,
            &dwarf,
            root_header.encoding(),
            format,
        )
    }

    /// Add input objects referenced by executable to the DWARF package.
    #[tracing::instrument(level = "trace")]
    pub fn add_executable(
        &mut self,
        path: &Path,
        missing_behaviour: MissingReferencedObjectBehaviour,
    ) -> Result<()> {
        let data = self.sess.read_input(path).map_err(Error::ReadInput)?;
        let obj = object::File::parse(data).map_err(Error::ParseObjectFile)?;

        let mut load_section =
            |id: gimli::SectionId| -> Result<_> { load_file_section(self.sess, id, &obj, false) };

        let dwarf = gimli::Dwarf::load(&mut load_section)?;

        let mut iter = dwarf.units();
        while let Some(header) = iter.next().map_err(Error::ParseUnitHeader)? {
            let unit = dwarf.unit(header).map_err(Error::ParseUnit)?;

            let target = match dwo_identifier_of_unit(&unit) {
                Some(target) => target,
                None => continue,
            };

            let dwo_name = {
                let mut cursor = unit.header.entries(&unit.abbreviations);
                cursor.next_dfs()?;
                let root = cursor.current().expect("unit without root debugging information entry");

                let dwo_name = if let Some(val) = root.attr_value(gimli::DW_AT_dwo_name)? {
                    // DWARF 5
                    val
                } else if let Some(val) = root.attr_value(gimli::DW_AT_GNU_dwo_name)? {
                    // GNU Extension
                    val
                } else {
                    return Err(Error::MissingDwoName(target.index()));
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

            // Only add `DwoId`s to the targets, not `DebugTypeSignature`s. There doesn't
            // appear to be a "skeleton type unit" to find the corresponding unit of (there are
            // normal type units in an executable, but should we expect to find a corresponding
            // split type unit for those?).
            if matches!(target, DwarfObjectIdentifier::Compilation(_)) {
                // Input objects are processed first, if a DWARF object referenced by this
                // executable was already found then don't add it to the target and try to add it
                // again.
                if let Some(package) = &self.maybe_in_progress {
                    if package.contained_units().contains(&target) {
                        continue;
                    }
                }

                debug!(?target, "adding target");
                self.targets.insert(target);
            }

            match self.add_input_object(&path) {
                Ok(()) => (),
                Err(Error::ReadInput(..)) if missing_behaviour.skip_missing() => (),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Add an input object to the DWARF package.
    ///
    /// Input object must be an archive or an elf object.
    #[tracing::instrument(level = "trace")]
    pub fn add_input_object(&mut self, path: &Path) -> Result<()> {
        let data = self.sess.read_input(&path).map_err(Error::ReadInput)?;

        let kind = FileKind::parse(data).map_err(Error::ParseFileKind)?;
        trace!(?kind);
        match kind {
            FileKind::Archive => {
                let archive = object::read::archive::ArchiveFile::parse(data)
                    .map_err(Error::ParseArchiveFile)?;

                for member in archive.members() {
                    let member = member.map_err(Error::ParseArchiveMember)?;
                    let data = member.data(data)?;

                    let kind = FileKind::parse(data).map_err(Error::ParseFileKind)?;
                    trace!(?kind, "archive member");
                    match kind {
                        FileKind::Elf32 | FileKind::Elf64 => {
                            let obj = object::File::parse(data).map_err(Error::ParseObjectFile)?;
                            self.process_input_object(&obj)?;
                        }
                        _ => {
                            trace!("skipping non-elf archive member");
                        }
                    }
                }

                Ok(())
            }
            FileKind::Elf32 | FileKind::Elf64 => {
                let obj = object::File::parse(data).map_err(Error::ParseObjectFile)?;
                self.process_input_object(&obj)
            }
            _ => Err(Error::InvalidInputKind),
        }
    }

    /// Returns the `object::write::Object` containing the created DWARF package.
    ///
    /// Returns an `Error::MissingReferencedUnit` if DWARF objects referenced by executables were
    /// not subsequently found.
    /// Returns an `Error::NoOutputObjectCreated` if no input objects or executables were provided.
    #[tracing::instrument(level = "trace")]
    pub fn finish(self) -> Result<WritableObject<'output>> {
        match self.maybe_in_progress {
            Some(package) => {
                if let Some(missing) = self.targets.difference(package.contained_units()).next() {
                    return Err(Error::MissingReferencedUnit(missing.index()));
                }

                package.finish()
            }
            None => Err(Error::NoOutputObjectCreated),
        }
    }
}
