pub extern crate object;

use std::{
    borrow::Cow,
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
    rc::Rc,
};

#[cfg(feature = "gc")]
use gimli::UnitType;
use gimli::{EndianSlice, Reader};
use hashbrown::HashMap;
use object::{write::Object as WritableObject, FileKind, Object, ObjectSection};
use tracing::{debug, trace};

use crate::{
    error::Result,
    ext::EndianityExt,
    index::Bucketable,
    package::{dwo_identifier_of_unit, DwarfObject, InProgressDwarfPackage, SessionHolder},
    relocate::{add_relocations, Relocate, RelocationMap},
};

mod error;
mod ext;
#[cfg(feature = "gc")]
#[path = "gc.rs"]
pub(crate) mod gc;
#[cfg(not(feature = "gc"))]
#[path = "nogc.rs"]
pub(crate) mod gc;
mod index;
mod package;
mod relocate;
mod strings;

pub use crate::error::Error;
pub use crate::package::DwoId;

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

#[cfg_attr(not(feature = "gc"), allow(dead_code))]
struct ExecutableData<'session>(
    Rc<gimli::Dwarf<Relocate<'session, gimli::EndianSlice<'session, gimli::RunTimeEndian>>>>,
);

#[cfg_attr(not(feature = "gc"), allow(dead_code))]
struct DwoData {
    addr_size: u8,
    addr_base: gimli::DebugAddrBase<usize>,
    ranges_base: gimli::DebugRngListsBase<usize>,
}

#[cfg_attr(not(feature = "gc"), allow(dead_code))]
#[derive(Default)]
struct GarbageCollectionData<'session> {
    executable_data: HashMap<PathBuf, ExecutableData<'session>>,
    dwo_data: HashMap<DwoId, Vec<(PathBuf, DwoData)>>,
}

#[cfg_attr(not(feature = "gc"), allow(dead_code))]
impl<'session> GarbageCollectionData<'session> {
    fn put_data_for_executable(&mut self, path: &Path, data: ExecutableData<'session>) {
        self.executable_data.insert(path.to_path_buf(), data);
    }
    fn put_data_for_dwo(&mut self, executable_path: &'_ Path, dwo_id: DwoId, data: DwoData) {
        self.dwo_data.entry(dwo_id).or_default().push((executable_path.to_path_buf(), data));
    }
    fn get_data_for_executable(&self, path: &'_ Path) -> Option<&ExecutableData<'session>> {
        self.executable_data.get(path)
    }
    fn get_data_for_dwo(
        &self,
        dwo_id: DwoId,
    ) -> Option<Vec<(&ExecutableData<'session>, &DwoData)>> {
        let entries = self.dwo_data.get(&dwo_id)?;
        let r = entries
            .iter()
            .filter_map(|(path, dwo_data)| {
                self.executable_data.get(path).map(|exec| (exec, dwo_data))
            })
            .collect::<Vec<_>>();
        if r.is_empty() {
            return None;
        }
        Some(r)
    }
}

fn dwarf_from_executable<'session>(
    sess: &'session impl Session<RelocationMap>,
    path: &'_ Path,
) -> Result<gimli::Dwarf<Relocate<'session, gimli::EndianSlice<'session, gimli::RunTimeEndian>>>> {
    let data = sess.read_input(path).map_err(Error::ReadInput)?;
    let obj = object::File::parse(data).map_err(Error::ParseObjectFile)?;

    let exec_endian = obj.endianness().as_runtime_endian();

    let mut load_section = |id: gimli::SectionId| -> Result<_> {
        let mut relocations = RelocationMap::default();
        let data = match obj.section_by_name(&id.name()) {
            Some(ref section) => {
                add_relocations(&mut relocations, &obj, section)?;
                section.compressed_data()?.decompress()?
            }
            // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
            None => Cow::Owned(Vec::with_capacity(1)),
        };

        let data_ref = sess.alloc_owned_cow(data);
        let reader = EndianSlice::new(data_ref, exec_endian);
        let section = reader;
        let relocations = sess.alloc_relocation(relocations);
        Ok(Relocate { relocations, section, reader })
    };

    gimli::Dwarf::load(&mut load_section)
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
    #[cfg(feature = "gc")]
    gc_data: Option<GarbageCollectionData<'session>>,
    maybe_in_progress: Option<InProgressDwarfPackage<'output>>,
    targets: HashSet<DwarfObject>,
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
        Self {
            sess,
            #[cfg(feature = "gc")]
            gc_data: None,
            maybe_in_progress: None,
            targets: HashSet::new(),
        }
    }

    /// Add an input object to the in-progress package.
    #[tracing::instrument(level = "trace", skip(obj))]
    fn process_input_object<'input>(&mut self, obj: &'input object::File<'input>) -> Result<()> {
        if self.maybe_in_progress.is_none() {
            self.maybe_in_progress =
                Some(InProgressDwarfPackage::new(obj.architecture(), obj.endianness()));
        }

        let encoding = if let Some(section) = obj.section_by_name(".debug_info.dwo") {
            let data = section.compressed_data()?.decompress()?;
            let data_ref = self.sess.alloc_owned_cow(data);
            let debug_info = gimli::DebugInfo::new(data_ref, obj.endianness().as_runtime_endian());
            debug_info
                .units()
                .next()
                .map_err(Error::ParseUnitHeader)?
                .map(|root_header| root_header.encoding())
                .ok_or(Error::NoCompilationUnits)?
        } else {
            debug!("no `.debug_info.dwo` in input dwarf object");
            return Ok(());
        };

        let sess = self.sess;
        self.maybe_in_progress.as_mut().expect("`process_input_object` is broken").add_input_object(
            SessionHolder::SimpleSession(sess),
            obj,
            encoding,
        )
    }

    /// Calls F with the path of each dwo in the executable.
    fn iterate_executable_dwo<F>(
        &mut self,
        dwarf: &gimli::Dwarf<Relocate<gimli::EndianSlice<gimli::RunTimeEndian>>>,
        mut f: F,
    ) -> Result<()>
    where
        F: FnMut(&mut Self, &Path) -> Result<()>,
    {
        let mut iter = dwarf.units();
        while let Some(header) = iter.next().map_err(Error::ParseUnitHeader)? {
            let unit = dwarf.unit(header.clone()).map_err(Error::ParseUnit)?;

            let target = match dwo_identifier_of_unit(&dwarf.debug_abbrev, &unit.header)? {
                Some(target) => target,
                None => {
                    debug!("no target {:?}", header.offset());
                    continue;
                }
            };

            let dwo_name = {
                let mut cursor = unit.header.entries(&unit.abbreviations);
                cursor.next_dfs()?;
                let root = cursor.current().expect("unit w/out root debugging information entry");

                let dwo_name = if let Some(val) = root.attr_value(gimli::DW_AT_dwo_name) {
                    // DWARF 5
                    val
                } else if let Some(val) = root.attr_value(gimli::DW_AT_GNU_dwo_name) {
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
            if matches!(target, DwarfObject::Compilation(_)) {
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

            f(self, &path)?;
        }

        Ok(())
    }

    /// Add input objects referenced by executable to the DWARF package.
    #[tracing::instrument(level = "trace")]
    pub fn add_executable(
        &mut self,
        path: &Path,
        missing_behaviour: MissingReferencedObjectBehaviour,
    ) -> Result<()> {
        let dwarf = dwarf_from_executable(self.sess, path)?;
        self.iterate_executable_dwo(&dwarf, |this, path| match this.add_input_object(path) {
            Ok(()) => Ok(()),
            Err(Error::ReadInput(..)) if missing_behaviour.skip_missing() => Ok(()),
            Err(e) => Err(e),
        })
    }

    fn iterate_object<F>(&mut self, path: &'_ Path, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Self, &object::File) -> Result<()>,
    {
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

                    let kind = if let Ok(kind) = FileKind::parse(data) {
                        kind
                    } else {
                        trace!("skipping non-elf archive member");
                        continue;
                    };

                    trace!(?kind, "archive member");
                    match kind {
                        FileKind::Elf32 | FileKind::Elf64 => {
                            let obj = object::File::parse(data).map_err(Error::ParseObjectFile)?;
                            f(self, &obj)?;
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
                f(self, &obj)
            }
            _ => Err(Error::InvalidInputKind),
        }
    }

    /// Add an input object to the DWARF package.
    ///
    /// Input object must be an archive or an elf object.
    #[tracing::instrument(level = "trace")]
    pub fn add_input_object(&mut self, path: &Path) -> Result<()> {
        self.iterate_object(path, |this, obj| this.process_input_object(obj))
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
            None if !self.targets.is_empty() => {
                let first_missing_unit = self
                    .targets
                    .iter()
                    .next()
                    .copied()
                    .expect("non-empty map doesn't have first element");
                Err(Error::MissingReferencedUnit(first_missing_unit.index()))
            }
            None => Err(Error::NoOutputObjectCreated),
        }
    }

    #[cfg(feature = "gc")]
    #[tracing::instrument(level = "trace")]
    pub fn preprocess_gc_executable(&mut self, path: &Path) -> Result<()> {
        let dwarf = Rc::new(dwarf_from_executable(self.sess, path)?);
        let gc_data = self.gc_data.get_or_insert_default();
        gc_data.put_data_for_executable(path, ExecutableData(dwarf.clone()));

        let mut iter = dwarf.units();
        while let Some(header) = iter.next().map_err(Error::ParseUnitHeader)? {
            let unit = dwarf.unit(header.clone()).map_err(Error::ParseUnit)?;

            let target = match dwo_identifier_of_unit(&dwarf.debug_abbrev, &unit.header)? {
                Some(DwarfObject::Compilation(dwo_id)) => dwo_id,
                Some(_) => continue,
                None => {
                    debug!("skipping unit without DWO ID in executable skeleton");
                    continue;
                }
            };

            match header.type_() {
                UnitType::Skeleton(_) => {
                    // DWARF5: addr_base is in DW_AT_addr_base.
                    let mut cursor = unit.header.entries(&unit.abbreviations);
                    cursor.next_dfs()?;
                    if let Some(root) = cursor.current() {
                        if let Some(gimli::AttributeValue::DebugAddrBase(addr_base)) =
                            root.attr_value(gimli::DW_AT_addr_base)
                        {
                            let addr_size = header.address_size();
                            trace!(
                                ?target,
                                addr_size,
                                ?addr_base,
                                "found dwo data for DWARF5 skeleton CU"
                            );
                            gc_data.put_data_for_dwo(
                                path,
                                target,
                                DwoData {
                                    addr_size,
                                    addr_base,
                                    // Always 0 for DWARF 5.
                                    ranges_base: gimli::DebugRngListsBase(0),
                                },
                            );
                        }
                    }
                }
                UnitType::Compilation => {
                    // DWARF4 GNU extension: skeleton units have DW_AT_GNU_dwo_id,
                    // DW_AT_GNU_addr_base, and DW_AT_GNU_ranges_base. If no addr
                    // or ranges base is present, default to 0.
                    let mut cursor = unit.header.entries(&unit.abbreviations);
                    cursor.next_dfs()?;
                    if let Some(root) = cursor.current() {
                        // Check for DW_AT_GNU_dwo_id to identify skeleton units.
                        if let Some(gimli::AttributeValue::DwoId(_)) =
                            root.attr_value(gimli::constants::DW_AT_GNU_dwo_id)
                        {
                            // DW_AT_GNU_addr_base defaults to 0 if absent.
                            let addr_base = root
                                .attr_value(gimli::constants::DW_AT_GNU_addr_base)
                                .and_then(|v| {
                                    let gimli::AttributeValue::DebugAddrBase(base) = v else {
                                        return None;
                                    };
                                    Some(base)
                                })
                                .unwrap_or(gimli::DebugAddrBase(0));
                            // DW_AT_GNU_ranges_base defaults to 0 if absent.
                            let ranges_base = root
                                .attr_value(gimli::constants::DW_AT_GNU_ranges_base)
                                .and_then(|v| match v {
                                    gimli::AttributeValue::DebugRngListsBase(base) => Some(base),
                                    _ => None,
                                })
                                .unwrap_or(gimli::DebugRngListsBase(0));
                            let addr_size = header.address_size();
                            trace!(
                                ?target,
                                ?addr_base,
                                ?ranges_base,
                                addr_size,
                                "found dwo data for DWARF4 GNU skeleton CU"
                            );
                            gc_data.put_data_for_dwo(
                                path,
                                target,
                                DwoData { addr_size, addr_base, ranges_base },
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Add an input object to the in-progress package with GC.
    #[cfg(feature = "gc")]
    #[tracing::instrument(level = "trace", skip(obj))]
    fn process_gc_input_object<'input>(&mut self, obj: &'input object::File<'input>) -> Result<()> {
        if self.maybe_in_progress.is_none() {
            self.maybe_in_progress =
                Some(InProgressDwarfPackage::new(obj.architecture(), obj.endianness()));
        }

        let encoding = if let Some(section) = obj.section_by_name(".debug_info.dwo") {
            let data = section.compressed_data()?.decompress()?;
            let data_ref = self.sess.alloc_owned_cow(data);
            let debug_info = gimli::DebugInfo::new(data_ref, obj.endianness().as_runtime_endian());
            debug_info
                .units()
                .next()
                .map_err(Error::ParseUnitHeader)?
                .map(|root_header| root_header.encoding())
                .ok_or(Error::NoCompilationUnits)?
        } else {
            debug!("no `.debug_info.dwo` in input dwarf object");
            return Ok(());
        };

        let sess = self.sess;
        let gc_data = self.gc_data.as_ref().ok_or(Error::GcNotInitialized)?;
        self.maybe_in_progress.as_mut().expect("`process_input_object` is broken").add_input_object(
            SessionHolder::new_gc(sess, gc_data),
            obj,
            encoding,
        )
    }

    /// Add an input object to the DWARF package with GC.
    ///
    /// Input object must be an archive or an elf object.
    #[cfg(feature = "gc")]
    #[tracing::instrument(level = "trace")]
    pub fn add_gc_input_object(&mut self, path: &Path) -> Result<()> {
        self.iterate_object(path, |this, obj| this.process_gc_input_object(obj))
    }

    #[cfg(feature = "gc")]
    #[tracing::instrument(level = "trace")]
    pub fn add_gc_executable(
        &mut self,
        path: &Path,
        missing_behaviour: MissingReferencedObjectBehaviour,
    ) -> Result<()> {
        let dwarf = self.gc_data.as_ref().ok_or(Error::GcNotInitialized)?.get_data_for_executable(path)
            .expect("All executables passed to add_gc_executable() must have preprocess_gc_executable() called first.")
            .0
            .clone();
        self.iterate_executable_dwo(&dwarf, |this, path| match this.add_gc_input_object(path) {
            Ok(()) => Ok(()),
            Err(Error::ReadInput(..)) if missing_behaviour.skip_missing() => Ok(()),
            Err(e) => Err(e),
        })
    }
}
