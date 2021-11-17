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

/// DWARF packages come in pre-standard GNU extension format or DWARF 5 standardized format.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum PackageFormat {
    /// GNU's DWARF package file format (preceded standardized version from DWARF 5).
    ///
    /// See [specification](https://gcc.gnu.org/wiki/DebugFissionDWP).
    GnuExtension,
    /// DWARF 5-standardized package file format.
    ///
    /// See Sec 7.3.5 and Appendix F of [DWARF specification](https://dwarfstd.org/doc/DWARF5.pdf).
    DwarfStd,
}

/// Sections contained in an output package depending on format being created.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
enum OutputPackageSections {
    /// GNU's DWARF package file format (preceded standardized version from DWARF 5).
    ///
    /// See [specification](https://gcc.gnu.org/wiki/DebugFissionDWP).
    GnuExtension {
        /// Identifier for the `.debug_info.dwo` section in the object file being created.
        ///
        /// Contains concatenated compilation units from `.debug_info.dwo` sections of input DWARF
        /// objects with matching `DW_AT_GNU_dwo_id` attributes.
        /// DWARF objects.
        debug_info: SectionId,
        /// Identifier for the `.debug_abbrev.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_abbrev.dwo` sections from input DWARF objects.
        debug_abbrev: SectionId,
        /// Identifier for the `.debug_str.dwo` section in the object file being created.
        ///
        /// Contains a string table merged from the `.debug_str.dwo` sections of input DWARF
        /// objects.
        debug_str: SectionId,
        /// Identifier for the `.debug_types.dwo` section in the object file being created.
        ///
        /// Contains concatenated type units from `.debug_types.dwo` sections of input DWARF
        /// objects with matching type signatures.
        debug_types: SectionId,
        /// Identifier for the `.debug_line.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_line.dwo` sections from input DWARF objects.
        debug_line: SectionId,
        /// Identifier for the `.debug_loc.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_loc.dwo` sections from input DWARF objects.
        debug_loc: SectionId,
        /// Identifier for the `.debug_str_offsets.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_str_offsets.dwo` sections from input DWARF objects,
        /// re-written with offsets into the merged `.debug_str.dwo` section.
        debug_str_offsets: SectionId,
        /// Identifier for the `.debug_macinfo.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_macinfo.dwo` sections from input DWARF objects.
        debug_macinfo: SectionId,
        /// Identifier for the `.debug_macro.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_macro.dwo` sections from input DWARF objects.
        debug_macro: SectionId,
    },
    /// DWARF 5-standardized package file format.
    ///
    /// See Sec 7.3.5 and Appendix F of [DWARF specification](https://dwarfstd.org/doc/DWARF5.pdf).
    DwarfStd {
        /// Identifier for the `.debug_info.dwo` section in the object file being created.
        ///
        /// Contains concatenated split compilation and type units from `.debug_info.dwo` sections
        /// of input DWARF objects.
        debug_info: SectionId,
        /// Identifier for the `.debug_abbrev.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_abbrev.dwo` sections from input DWARF objects.
        debug_abbrev: SectionId,
        /// Identifier for the `.debug_str.dwo` section in the object file being created.
        ///
        /// Contains a string table merged from the `.debug_str.dwo` sections of input DWARF
        /// objects.
        debug_str: SectionId,
        /// Identifier for the `.debug_line.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_line.dwo` sections from input DWARF objects.
        debug_line: SectionId,
        /// Identifier for the `.debug_loclists.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_loclists.dwo` sections from input DWARF objects.
        debug_loclists: SectionId,
        /// Identifier for the `.debug_rnglists.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_rnglists.dwo` sections from input DWARF objects.
        debug_rnglists: SectionId,
        /// Identifier for the `.debug_str_offsets.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_str_offsets.dwo` sections from input DWARF objects,
        /// re-written with offsets into the merged `.debug_str.dwo` section.
        debug_str_offsets: SectionId,
        /// Identifier for the `.debug_macro.dwo` section in the object file being created.
        ///
        /// Contains concatenated `.debug_macro.dwo` sections from input DWARF objects.
        debug_macro: SectionId,
    },
}

/// In-progress DWARF package being produced.
struct OutputPackage<'file> {
    /// Object file being created.
    obj: write::Object<'file>,

    /// Identifier for the `.debug_cu_index.dwo` section in the object file being created. Format
    /// depends on whether this is a GNU extension-flavoured package or DWARF 5-flavoured package.
    debug_cu_index: SectionId,
    /// Identifier for the `.debug_tu_index.dwo` section in the object file being created. Format
    /// depends on whether this is a GNU extension-flavoured package or DWARF 5-flavoured package.
    debug_tu_index: SectionId,

    /// Non-index sections of a DWARF package depend on whether this is a GNU extension-flavoured
    /// package or a DWARF 5-flavoured package.
    sections: OutputPackageSections,
}

/// New-type'd index (constructed from `gimli::DwoID`) with a custom `Debug` implementation to
/// print in hexadecimal.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
struct DwoId(u64);

impl fmt::Debug for DwoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DwoId({:#x})", self.0)
    }
}

impl From<gimli::DwoId> for DwoId {
    fn from(dwo_id: gimli::DwoId) -> Self {
        Self(dwo_id.0)
    }
}

/// New-type'd index (constructed from `gimli::DebugTypeSignature`) with a custom `Debug`
/// implementation to print in hexadecimal.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
struct DebugTypeSignature(u64);

impl fmt::Debug for DebugTypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DebugTypeSignature({:#x})", self.0)
    }
}

impl From<gimli::DebugTypeSignature> for DebugTypeSignature {
    fn from(signature: gimli::DebugTypeSignature) -> Self {
        Self(signature.0)
    }
}

/// Identifier for a DWARF object.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum DwarfObjectIdentifier {
    /// `DwoId` identifying compilation units.
    Compilation(DwoId),
    /// `DebugTypeSignature` identifying type units.
    Type(DebugTypeSignature),
}

/// A DWARF object referenced by input object.
struct TargetDwarfObject {
    /// `DwoId` or `DebugTypeSignature` of the DWARF object, read from compilation unit header (or
    /// `DW_AT_GNU_dwo_id`).
    identifier: DwarfObjectIdentifier,
    /// Path to the DWARF object, read from `DW_AT_dwo_name`/`DW_AT_GNU_dwo_name`, prepended with
    /// `DW_AT_comp_dir`.
    path: PathBuf,
}

impl fmt::Debug for TargetDwarfObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} ({})",
            self.identifier,
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

trait IndexEntry: Bucketable {
    /// Return the number of columns in `.debug_{cu,tu}_index` required by this entry.
    fn number_of_columns(&self) -> u32;

    /// Return the signature of the entry (`DwoId` or `DebugTypeSignature`).
    fn signature(&self) -> u64;

    /// Write the header for the index entry (e.g. `gimli::DW_SECT_INFO` constants)
    ///
    /// Only uses the entry to know which columns exist (invariant: every entry has the same
    /// number of columns).
    fn write_header<Endian: gimli::Endianity>(
        &self,
        format: PackageFormat,
        out: &mut EndianVec<Endian>,
    ) -> Result<()>;

    /// Write the contribution for the index entry to `out`, component of `Contribution` written is
    /// chosen by `proj` closure.
    fn write_contribution<Endian, Proj>(
        &self,
        out: &mut EndianVec<Endian>,
        proj: Proj,
    ) -> Result<()>
    where
        Endian: gimli::Endianity,
        Proj: Fn(Contribution) -> u32;
}

impl<T: IndexEntry> Bucketable for T {
    fn index(&self) -> u64 {
        self.signature()
    }
}

/// Type alias for the size of a compilation/type unit's contribution.
type ContributionSize = u64;

/// Contribution to a section - offset and size.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct Contribution {
    /// Offset of this contribution into its containing section.
    offset: ContributionOffset,
    /// Size of this contribution in its containing section.
    size: ContributionSize,
}

/// Entry into the `.debug_tu_index` section.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct TuIndexEntry {
    type_signature: DebugTypeSignature,
    debug_info_or_types: Contribution,
    debug_abbrev: Contribution,
    debug_line: Option<Contribution>,
    debug_str_offsets: Option<Contribution>,
}

impl IndexEntry for TuIndexEntry {
    fn number_of_columns(&self) -> u32 {
        2 /* info/types and abbrev are required columns */
        + self.debug_line.map_or(0, |_| 1)
        + self.debug_str_offsets.map_or(0, |_| 1)
    }

    fn signature(&self) -> u64 {
        self.type_signature.0
    }

    fn write_header<Endian: gimli::Endianity>(
        &self,
        format: PackageFormat,
        out: &mut EndianVec<Endian>,
    ) -> Result<()> {
        match format {
            PackageFormat::GnuExtension => {
                out.write_u32(gimli::DW_SECT_V2_TYPES.0)?;
                out.write_u32(gimli::DW_SECT_V2_ABBREV.0)?;
                if self.debug_line.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_LINE.0)?;
                }
                if self.debug_str_offsets.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_STR_OFFSETS.0)?;
                }
            }
            PackageFormat::DwarfStd => {
                out.write_u32(gimli::DW_SECT_INFO.0)?;
                out.write_u32(gimli::DW_SECT_ABBREV.0)?;
                if self.debug_line.is_some() {
                    out.write_u32(gimli::DW_SECT_LINE.0)?;
                }
                if self.debug_str_offsets.is_some() {
                    out.write_u32(gimli::DW_SECT_STR_OFFSETS.0)?;
                }
            }
        }

        Ok(())
    }

    fn write_contribution<Endian, Proj>(
        &self,
        out: &mut EndianVec<Endian>,
        proj: Proj,
    ) -> Result<()>
    where
        Endian: gimli::Endianity,
        Proj: Fn(Contribution) -> u32,
    {
        out.write_u32(proj(self.debug_info_or_types))?;
        out.write_u32(proj(self.debug_abbrev))?;
        if let Some(debug_line) = self.debug_line {
            out.write_u32(proj(debug_line))?;
        }
        if let Some(debug_str_offsets) = self.debug_str_offsets {
            out.write_u32(proj(debug_str_offsets))?;
        }
        Ok(())
    }
}

/// Entry into the `.debug_cu_index` section.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct CuIndexEntry {
    dwo_id: DwoId,
    kind: CuIndexEntryKind,
}

/// Contributions from sections for the current index entry. Relevant sections depend on GNU
/// extension or DWARF 5 package format.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum CuIndexEntryKind {
    GnuExtension {
        debug_info: Contribution,
        debug_abbrev: Contribution,
        debug_line: Option<Contribution>,
        debug_loc: Option<Contribution>,
        debug_str_offsets: Option<Contribution>,
        debug_macinfo: Option<Contribution>,
        debug_macro: Option<Contribution>,
    },
    DwarfStd {
        debug_info: Contribution,
        debug_abbrev: Contribution,
        debug_line: Option<Contribution>,
        debug_loclists: Option<Contribution>,
        debug_rnglists: Option<Contribution>,
        debug_str_offsets: Option<Contribution>,
        debug_macro: Option<Contribution>,
    },
}

impl IndexEntry for CuIndexEntry {
    fn number_of_columns(&self) -> u32 {
        match self.kind {
            CuIndexEntryKind::GnuExtension {
                debug_line,
                debug_loc,
                debug_str_offsets,
                debug_macinfo,
                debug_macro,
                ..
            } => {
                2 /* info and abbrev are required columns */
                + debug_line.map_or(0, |_| 1)
                + debug_loc.map_or(0, |_| 1)
                + debug_str_offsets.map_or(0, |_| 1)
                + debug_macinfo.map_or(0, |_| 1)
                + debug_macro.map_or(0, |_| 1)
            }
            CuIndexEntryKind::DwarfStd {
                debug_line,
                debug_loclists,
                debug_rnglists,
                debug_str_offsets,
                debug_macro,
                ..
            } => {
                2 /* info and abbrev are required columns */
                + debug_line.map_or(0, |_| 1)
                + debug_loclists.map_or(0, |_| 1)
                + debug_rnglists.map_or(0, |_| 1)
                + debug_str_offsets.map_or(0, |_| 1)
                + debug_macro.map_or(0, |_| 1)
            }
        }
    }

    fn signature(&self) -> u64 {
        self.dwo_id.0
    }

    fn write_header<Endian: gimli::Endianity>(
        &self,
        _: PackageFormat,
        out: &mut EndianVec<Endian>,
    ) -> Result<()> {
        match self.kind {
            CuIndexEntryKind::GnuExtension {
                debug_line,
                debug_loc,
                debug_str_offsets,
                debug_macinfo,
                debug_macro,
                ..
            } => {
                out.write_u32(gimli::DW_SECT_V2_INFO.0)?;
                out.write_u32(gimli::DW_SECT_V2_ABBREV.0)?;
                if debug_line.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_LINE.0)?;
                }
                if debug_loc.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_LOC.0)?;
                }
                if debug_str_offsets.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_STR_OFFSETS.0)?;
                }
                if debug_macinfo.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_MACINFO.0)?;
                }
                if debug_macro.is_some() {
                    out.write_u32(gimli::DW_SECT_V2_MACRO.0)?;
                }
            }
            CuIndexEntryKind::DwarfStd {
                debug_line,
                debug_loclists,
                debug_rnglists,
                debug_str_offsets,
                debug_macro,
                ..
            } => {
                out.write_u32(gimli::DW_SECT_INFO.0)?;
                out.write_u32(gimli::DW_SECT_ABBREV.0)?;
                if debug_line.is_some() {
                    out.write_u32(gimli::DW_SECT_LINE.0)?;
                }
                if debug_loclists.is_some() {
                    out.write_u32(gimli::DW_SECT_LOCLISTS.0)?;
                }
                if debug_rnglists.is_some() {
                    out.write_u32(gimli::DW_SECT_RNGLISTS.0)?;
                }
                if debug_str_offsets.is_some() {
                    out.write_u32(gimli::DW_SECT_STR_OFFSETS.0)?;
                }
                if debug_macro.is_some() {
                    out.write_u32(gimli::DW_SECT_MACRO.0)?;
                }
            }
        }

        Ok(())
    }

    fn write_contribution<Endian, Proj>(
        &self,
        out: &mut EndianVec<Endian>,
        proj: Proj,
    ) -> Result<()>
    where
        Endian: gimli::Endianity,
        Proj: Fn(Contribution) -> u32,
    {
        match self.kind {
            CuIndexEntryKind::GnuExtension {
                debug_info,
                debug_abbrev,
                debug_line,
                debug_loc,
                debug_str_offsets,
                debug_macinfo,
                debug_macro,
            } => {
                out.write_u32(proj(debug_info))?;
                out.write_u32(proj(debug_abbrev))?;
                if let Some(debug_line) = debug_line {
                    out.write_u32(proj(debug_line))?;
                }
                if let Some(debug_loc) = debug_loc {
                    out.write_u32(proj(debug_loc))?;
                }
                if let Some(debug_str_offsets) = debug_str_offsets {
                    out.write_u32(proj(debug_str_offsets))?;
                }
                if let Some(debug_macinfo) = debug_macinfo {
                    out.write_u32(proj(debug_macinfo))?;
                }
                if let Some(debug_macro) = debug_macro {
                    out.write_u32(proj(debug_macro))?;
                }
            }
            CuIndexEntryKind::DwarfStd {
                debug_info,
                debug_abbrev,
                debug_line,
                debug_loclists,
                debug_rnglists,
                debug_str_offsets,
                debug_macro,
            } => {
                out.write_u32(proj(debug_info))?;
                out.write_u32(proj(debug_abbrev))?;
                if let Some(debug_line) = debug_line {
                    out.write_u32(proj(debug_line))?;
                }
                if let Some(debug_loclists) = debug_loclists {
                    out.write_u32(proj(debug_loclists))?;
                }
                if let Some(debug_rnglists) = debug_rnglists {
                    out.write_u32(proj(debug_rnglists))?;
                }
                if let Some(debug_str_offsets) = debug_str_offsets {
                    out.write_u32(proj(debug_str_offsets))?;
                }
                if let Some(debug_macro) = debug_macro {
                    out.write_u32(proj(debug_macro))?;
                }
            }
        }

        Ok(())
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

/// Helper function to return the name of a section in a dwarf object.
///
/// Unnecessary but works around a bug in Gimli.
fn dwo_name(id: gimli::SectionId) -> &'static str {
    match id {
        // TODO: patch gimli to return this
        gimli::SectionId::DebugMacinfo => ".debug_macinfo.dwo",
        _ => id.dwo_name().unwrap(),
    }
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

/// Returns the `DwoId` or `DebugTypeSignature` of a unit.
///
/// **DWARF 5:**
///
/// - `DwoId` is in the unit header of a skeleton unit (identifying the split compilation unit
/// that contains the debuginfo) or split compilation unit (identifying the skeleton unit that this
/// debuginfo corresponds to).
/// - `DebugTypeSignature` is in the unit header of a split type unit.
///
/// **Earlier DWARF versions with GNU extension:**
///
/// - `DW_AT_GNU_dwo_id` attribute of the DIE contains the `DwoId`.
#[tracing::instrument(level = "trace", skip(unit))]
fn dwo_identifier_of_unit<R: gimli::Reader>(
    unit: &gimli::Unit<R>,
) -> Option<DwarfObjectIdentifier> {
    match unit.header.type_() {
        // DWARF 5
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => {
            Some(DwarfObjectIdentifier::Compilation(dwo_id.into()))
        }
        UnitType::SplitType { type_signature, .. } => {
            Some(DwarfObjectIdentifier::Type(type_signature.into()))
        }
        // GNU Extension (maybe!)
        UnitType::Compilation => {
            unit.dwo_id.map(|id| DwarfObjectIdentifier::Compilation(id.into()))
        }
        // Wrong compilation unit type.
        _ => None,
    }
}

/// Returns the `TargetDwarfObject` of a compilation/type unit.
///
/// In DWARF 5, skeleton compilation unit will contain a `DW_AT_dwo_name` attribute with the name
/// of the dwarf object file containing the split compilation unit with the `DwoId`. In earlier
/// DWARF versions with GNU extension, `DW_AT_GNU_dwo_name` attribute contains a name.
#[tracing::instrument(level = "trace", skip(dwarf, unit))]
fn dwo_id_and_path_of_unit<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
) -> Result<Option<TargetDwarfObject>> {
    let identifier = if let Some(identifier) = dwo_identifier_of_unit(unit) {
        identifier
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

    Ok(Some(TargetDwarfObject { identifier, path }))
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
#[tracing::instrument(level = "trace")]
fn create_output_object<'file>(
    format: PackageFormat,
    architecture: Architecture,
    endianness: Endianness,
) -> Result<OutputPackage<'file>> {
    use gimli::SectionId::*;

    let mut obj = write::Object::new(BinaryFormat::Elf, architecture, endianness);

    let mut add_section = |gimli_id: gimli::SectionId| -> SectionId {
        obj.add_section(Vec::new(), dwo_name(gimli_id).as_bytes().to_vec(), SectionKind::Debug)
    };

    let debug_cu_index = add_section(DebugCuIndex);
    let debug_tu_index = add_section(DebugTuIndex);

    let sections = match format {
        PackageFormat::GnuExtension => OutputPackageSections::GnuExtension {
            debug_info: add_section(DebugInfo),
            debug_abbrev: add_section(DebugAbbrev),
            debug_str: add_section(DebugStr),
            debug_types: add_section(DebugTypes),
            debug_line: add_section(DebugLine),
            debug_loc: add_section(DebugLoc),
            debug_str_offsets: add_section(DebugStrOffsets),
            debug_macinfo: add_section(DebugMacinfo),
            debug_macro: add_section(DebugMacro),
        },
        PackageFormat::DwarfStd => OutputPackageSections::DwarfStd {
            debug_info: add_section(DebugInfo),
            debug_abbrev: add_section(DebugAbbrev),
            debug_str: add_section(DebugStr),
            debug_line: add_section(DebugLine),
            debug_loclists: add_section(DebugLocLists),
            debug_rnglists: add_section(DebugRngLists),
            debug_str_offsets: add_section(DebugStrOffsets),
            debug_macro: add_section(DebugMacro),
        },
    };

    Ok(OutputPackage { obj, debug_cu_index, debug_tu_index, sections })
}

/// Read the string offsets from `.debug_str_offsets.dwo` in the DWARF object, adding each to the
/// in-progress `.debug_str` (`DwpStringTable`) and building a new `.debug_str_offsets.dwo` to be
/// the current DWARF object's contribution to the DWARF package.
#[tracing::instrument(level = "trace", skip(string_table, input, input_dwarf, output))]
fn append_str_offsets<'input, 'output, 'arena: 'input, Endian: gimli::Endianity>(
    format: PackageFormat,
    string_table: &mut DwpStringTable<Endian>,
    input: &object::File<'input>,
    input_dwarf: &gimli::Dwarf<DwpReader<'arena>>,
    output: &mut write::Object<'output>,
    output_id: SectionId,
) -> Result<Option<Contribution>> {
    let section_name = gimli::SectionId::DebugStrOffsets.dwo_name().unwrap();
    let section = match input.section_by_name(section_name) {
        Some(section) => section,
        // `.debug_str_offsets.dwo` is an optional section.
        None => return Ok(None),
    };
    let section_size = section.size();

    // TODO: Write the DWARF 5 string offset table header (how does it work w/r/t concatenation?)
    let mut data = EndianVec::new(runtime_endian_of_object(input));

    let root_header = input_dwarf.units().next()?.context(DwpError::DwarfObjectWithNoUnits)?;
    let encoding = root_header.encoding();
    let base = DebugStrOffsetsBase::default_for_encoding_and_file(encoding, DwarfFileType::Dwo);

    let entry_size = match encoding.format {
        Format::Dwarf32 => 4,
        Format::Dwarf64 => 8,
    };

    let num_elements = section_size / entry_size;
    debug!(?section_size, ?num_elements);

    for i in 0..num_elements {
        let dwo_index = DebugStrOffsetsIndex(i as usize);
        let dwo_offset =
            input_dwarf.debug_str_offsets.get_str_offset(encoding.format, base, dwo_index)?;
        let dwo_str = input_dwarf.debug_str.get_str(dwo_offset)?;
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

    let offset = output.append_section_data(output_id, &data.into_vec(), section.align());
    Ok(Some(Contribution {
        offset: ContributionOffset(offset),
        size: section_size.try_into().expect("too large for u32"),
    }))
}

/// Append a unit from the input DWARF object to the `.debug_info` (or `.debug_types`) section in
/// the output object. Only appends unit if it has a `DwarfObjectIdentifier` matching the target
/// `DwarfObjectIdentifier`.
#[tracing::instrument(level = "trace", skip_all)]
fn append_unit<'input, 'arena, 'output: 'arena, CuOp, Sect, TuOp>(
    dwo: &TargetDwarfObject,
    section: &Sect,
    unit: &gimli::Unit<DwpReader<'arena>>,
    output: &mut write::Object<'output>,
    mut create_cu_entry: CuOp,
    mut create_tu_entry: TuOp,
) -> Result<()>
where
    CuOp: FnMut(&mut write::Object<'output>, DwoId, &[u8], u64),
    TuOp: FnMut(&mut write::Object<'output>, DebugTypeSignature, &[u8], u64),
    Sect: ObjectSection<'input>,
{
    let length: u64 = unit.header.length_including_self().try_into().unwrap();
    let offset = unit.header.offset();

    let identifier = dwo_identifier_of_unit(&unit);
    match (unit.header.type_(), identifier, dwo.identifier) {
        (
            UnitType::Compilation | UnitType::SplitCompilation(..),
            Some(DwarfObjectIdentifier::Compilation(dwo_id)),
            DwarfObjectIdentifier::Compilation(target_dwo_id),
        ) if dwo_id == target_dwo_id => {
            let offset = offset.as_debug_info_offset().unwrap().0;
            let data = section
                .data_range(offset.try_into().unwrap(), length)?
                .ok_or(DwpError::CompilationUnitWithNoData)?;

            create_cu_entry(output, dwo_id, data, length);
            Ok(())
        }
        (
            UnitType::Compilation | UnitType::SplitType { .. },
            Some(DwarfObjectIdentifier::Type(type_signature)),
            DwarfObjectIdentifier::Type(target_type_signature),
        ) if type_signature == target_type_signature => {
            let offset = offset.as_debug_types_offset().unwrap().0;
            let data = section
                .data_range(offset.try_into().unwrap(), length)?
                .ok_or(DwpError::CompilationUnitWithNoData)?;

            create_tu_entry(output, type_signature, data, length);
            Ok(())
        }
        (_, Some(..), _) => Err(anyhow!(DwpError::DwarfObjectCompilationUnitWithDwoIdNotSplitUnit)),
        (_, None, _) => Ok(()),
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
    let name = dwo_name(input_id);
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
    tu_index_entries: &mut Vec<TuIndexEntry>,
    string_table: &mut DwpStringTable<Endian>,
    output: &mut OutputPackage<'output>,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_mmap: &'arena Arena<Mmap>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<()> {
    use gimli::SectionId::*;

    let dwo_obj = load_object_file(&arena_mmap, &dwo.path)?;

    let mut load_dwo_section = |id: gimli::SectionId| -> Result<_> {
        load_file_section(id, &dwo_obj, true, &arena_data, &arena_relocations)
    };

    let mut append_section = |from: gimli::SectionId, to: SectionId, reqd: bool| -> Result<_> {
        append_section(&dwo_obj, from, &mut output.obj, to, reqd)
    };

    let debug_info_name = gimli::SectionId::DebugInfo.dwo_name().unwrap();
    let debug_info_section = dwo_obj
        .section_by_name(debug_info_name)
        .with_context(|| DwpError::DwarfObjectMissingSection(debug_info_name.to_string()))?;

    let mut dwo_dwarf = gimli::Dwarf::load(&mut load_dwo_section)?;
    dwo_dwarf.debug_addr = parent_debug_addr;

    match output.sections {
        OutputPackageSections::GnuExtension {
            debug_info,
            debug_abbrev,
            debug_types,
            debug_line,
            debug_loc,
            debug_str_offsets,
            debug_macinfo,
            debug_macro,
            ..
        } => {
            let debug_abbrev = append_section(DebugAbbrev, debug_abbrev, true)?
                .expect("required section didn't return error");
            let debug_line = append_section(DebugLine, debug_line, false)?;
            let debug_loc = append_section(DebugLoc, debug_loc, false)?;
            let debug_macinfo = append_section(DebugMacinfo, debug_macinfo, false)?;
            let debug_macro = append_section(DebugMacro, debug_macro, false)?;

            let debug_str_offsets = append_str_offsets(
                PackageFormat::GnuExtension,
                string_table,
                &dwo_obj,
                &dwo_dwarf,
                &mut output.obj,
                debug_str_offsets,
            )?;

            let mut iter = dwo_dwarf.units();
            while let Some(header) = iter.next()? {
                let unit = dwo_dwarf.unit(header)?;
                append_unit(
                    &dwo,
                    &debug_info_section,
                    &unit,
                    &mut output.obj,
                    |output, dwo_id, unit_data, unit_size| {
                        let offset = output.append_section_data(
                            debug_info,
                            unit_data,
                            debug_info_section.align(),
                        );
                        let debug_info =
                            Contribution { offset: ContributionOffset(offset), size: unit_size };
                        cu_index_entries.push(CuIndexEntry {
                            dwo_id,
                            kind: CuIndexEntryKind::GnuExtension {
                                debug_info,
                                debug_abbrev,
                                debug_line,
                                debug_loc,
                                debug_str_offsets,
                                debug_macinfo,
                                debug_macro,
                            },
                        });
                    },
                    |_, _, _, _| { /* no-op, no types in `.debug_info` on DWARF 4 */ },
                )?;
            }

            let debug_types_name = gimli::SectionId::DebugTypes.dwo_name().unwrap();
            if let Some(debug_types_section) = dwo_obj.section_by_name(debug_types_name) {
                let mut iter = dwo_dwarf.type_units();
                while let Some(header) = iter.next()? {
                    let unit = dwo_dwarf.unit(header)?;
                    append_unit(
                        &dwo,
                        &debug_types_section,
                        &unit,
                        &mut output.obj,
                        |_, _, _, _| { /* no-op, no compilation units in `.debug_types` */ },
                        |output, type_signature, unit_data, unit_size| {
                            let offset = output.append_section_data(
                                debug_types,
                                unit_data,
                                debug_types_section.align(),
                            );
                            let debug_types = Contribution {
                                offset: ContributionOffset(offset),
                                size: unit_size,
                            };
                            tu_index_entries.push(TuIndexEntry {
                                type_signature,
                                debug_info_or_types: debug_types,
                                debug_abbrev,
                                debug_line,
                                debug_str_offsets,
                            });
                        },
                    )?;
                }
            }
        }
        OutputPackageSections::DwarfStd {
            debug_info,
            debug_abbrev,
            debug_line,
            debug_loclists,
            debug_rnglists,
            debug_str_offsets,
            debug_macro,
            ..
        } => {
            let debug_abbrev = append_section(DebugAbbrev, debug_abbrev, true)?
                .expect("required section didn't return error");
            let debug_line = append_section(DebugLine, debug_line, false)?;
            let debug_loclists = append_section(DebugLocLists, debug_loclists, false)?;
            let debug_rnglists = append_section(DebugRngLists, debug_rnglists, false)?;
            let debug_macro = append_section(DebugMacro, debug_macro, false)?;

            let debug_str_offsets = append_str_offsets(
                PackageFormat::DwarfStd,
                string_table,
                &dwo_obj,
                &dwo_dwarf,
                &mut output.obj,
                debug_str_offsets,
            )?;

            let mut iter = dwo_dwarf.units();
            while let Some(header) = iter.next()? {
                let unit = dwo_dwarf.unit(header)?;
                append_unit(
                    &dwo,
                    &debug_info_section,
                    &unit,
                    &mut output.obj,
                    |output, dwo_id, unit_data, unit_size| {
                        let offset = output.append_section_data(
                            debug_info,
                            unit_data,
                            debug_info_section.align(),
                        );
                        let debug_info =
                            Contribution { offset: ContributionOffset(offset), size: unit_size };
                        cu_index_entries.push(CuIndexEntry {
                            dwo_id,
                            kind: CuIndexEntryKind::DwarfStd {
                                debug_info,
                                debug_abbrev,
                                debug_line,
                                debug_loclists,
                                debug_rnglists,
                                debug_str_offsets,
                                debug_macro,
                            },
                        });
                    },
                    |output, type_signature, unit_data, unit_size| {
                        let offset = output.append_section_data(
                            debug_info,
                            unit_data,
                            debug_info_section.align(),
                        );
                        let debug_info =
                            Contribution { offset: ContributionOffset(offset), size: unit_size };
                        tu_index_entries.push(TuIndexEntry {
                            type_signature,
                            debug_info_or_types: debug_info,
                            debug_abbrev,
                            debug_line,
                            debug_str_offsets,
                        });
                    },
                )?;
            }
        }
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
    let num_buckets = if elements.len() < 2 { 2 } else { next_pow2(3 * unit_count / 2) };
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
fn write_index<'output, Endian, Entry>(
    endianness: Endian,
    format: PackageFormat,
    entries: &[Entry],
    output: &mut write::Object<'output>,
    output_id: SectionId,
) -> Result<()>
where
    Endian: gimli::Endianity,
    Entry: IndexEntry + fmt::Debug,
{
    if entries.len() == 0 {
        return Ok(());
    }

    let mut out = EndianVec::new(endianness);

    let buckets = bucket(entries);
    debug!(?buckets);

    let num_columns = entries[0].number_of_columns();
    assert!(entries.iter().all(|e| e.number_of_columns() == num_columns));
    debug!(?num_columns);

    // Write header..
    match format {
        PackageFormat::GnuExtension => {
            // GNU Extension
            out.write_u32(2)?;
        }
        PackageFormat::DwarfStd => {
            // DWARF 5
            out.write_u32(5)?;
            // Reserved padding
            out.write_u32(0)?;
        }
    }

    // Columns (e.g. info, abbrev, loc, etc.)
    out.write_u32(num_columns)?;
    // Number of units
    out.write_u32(entries.len().try_into().unwrap())?;
    // Number of buckets
    out.write_u32(buckets.len().try_into().unwrap())?;

    // Write signatures..
    for i in &buckets {
        if *i > 0 {
            out.write_u64(entries[(*i - 1) as usize].signature())?;
        } else {
            out.write_u64(0)?;
        }
    }

    // Write indices..
    for i in &buckets {
        out.write_u32(*i)?;
    }

    // Write column headers..
    entries[0].write_header(format, &mut out)?;

    // Write offsets..
    let write_offset = |contrib: Contribution| contrib.offset.0.try_into().unwrap();
    for entry in entries {
        entry.write_contribution(&mut out, write_offset)?;
    }

    // Write sizes..
    let write_size = |contrib: Contribution| contrib.size.try_into().unwrap();
    for entry in entries {
        entry.write_contribution(&mut out, write_size)?;
    }

    // FIXME: use the correct alignment here
    let _ = output.append_section_data(output_id, &out.into_vec(), 1);
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

    let format = PackageFormat::GnuExtension;
    let mut output = create_output_object(format, obj.architecture(), obj.endianness())?;
    let mut string_table = DwpStringTable::new(endianness);

    let mut cu_index_entries = Vec::new();
    let mut tu_index_entries = Vec::new();

    for dwo in dwarf_objects {
        process_dwarf_object(
            parent_debug_addr.clone(),
            dwo,
            &mut cu_index_entries,
            &mut tu_index_entries,
            &mut string_table,
            &mut output,
            &arena_data,
            &arena_mmap,
            &arena_relocations,
        )?;
    }

    // Write the merged string table to the `.debug_str.dwo` section.
    match output.sections {
        OutputPackageSections::GnuExtension { debug_str, .. }
        | OutputPackageSections::DwarfStd { debug_str, .. } => {
            let _ = string_table.write(&mut output.obj, debug_str);
        }
    }

    // Write `.debug_cu_index` and `.debug_tu_index`
    write_index(endianness, format, &cu_index_entries, &mut output.obj, output.debug_cu_index)?;
    write_index(endianness, format, &tu_index_entries, &mut output.obj, output.debug_tu_index)?;

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
