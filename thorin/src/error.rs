use thiserror::Error;

use crate::package::DwarfObjectIdentifier;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Diagnostics (and contexts) emitted during DWARF packaging.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to read input file")]
    ReadInput(#[source] std::io::Error),
    #[error("Failed to parse kind of input file")]
    ParseFileKind(#[source] object::Error),
    #[error("Failed to parse object file `{1}`")]
    ParseObjectFile(#[source] object::Error, String),
    #[error("Failed to parse archive file `{1}`")]
    ParseArchiveFile(#[source] object::Error, String),
    #[error("Failed to parse archive member")]
    ParseArchiveMember(#[source] object::Error),
    #[error("Failed to decompress data")]
    DecompressData(#[source] object::Error),
    #[error("Section without name at offset 0x{1:08x}")]
    NamelessSection(#[source] object::Error, usize),
    #[error("Relocation with invalid symbol for section `{0}` at offset 0x{1:08x}")]
    RelocationWithInvalidSymbol(String, usize),
    #[error("Multiple relocations for section `{0}` at offset 0x{1:08x}")]
    MultipleRelocations(String, usize),
    #[error("Unsupported relocation for section {0} at offset 0x{1:08x}")]
    UnsupportedRelocation(String, usize),
    #[error("Failed loading executable `{0}`")]
    LoadingExecutable(String),
    #[error("Missing path attribute to DWARF object 0x{0:08x}")]
    MissingDwoName(u64),
    #[error("Input DWARF object missing required section `{0}`")]
    MissingRequiredSection(&'static str),
    #[error("Failed to parse unit header")]
    ParseUnitHeader(#[source] gimli::read::Error),
    #[error("Failed to parse unit")]
    ParseUnit(#[source] gimli::read::Error),
    #[error("Failed to concatenate `{1}` section from input DWARF object")]
    AppendSection(#[source] object::Error, &'static str),
    #[error("Failed to read header of `.debug_str_offsets.dwo` section")]
    StrOffsetsMissingHeader,
    #[error("Failed to read offset at index {1} of `.debug_str_offsets.dwo` section")]
    OffsetAtIndex(#[source] gimli::read::Error, u64),
    #[error("Failed to read string at offset {1:08x} of `.debug_str.dwo` section")]
    StrAtOffset(#[source] gimli::read::Error, usize),
    #[error("Failed to write string to in-progress `.debug_str.dwo` section")]
    WritingStrToStringTable(#[source] gimli::write::Error),
    #[error("Failed to parse index section")]
    ParseIndex(#[source] gimli::read::Error),
    #[error("Unit 0x{0:08x} from input DWARF package is not in its index")]
    UnitNotInIndex(u64),
    #[error("Row {0} found in index's hash table not present in index")]
    RowNotInIndex(#[source] gimli::read::Error, u32),
    #[error("Section not found in unit's row in index")]
    SectionNotInRow,
    #[error("Unit `{0}` in input DWARF object with no data")]
    EmptyUnit(u64),
    #[error("Failed to write `.debug_cu_index` of output DWARF package")]
    WriteCuIndex(#[source] gimli::write::Error),
    #[error("Failed to write `.debug_tu_index` of output DWARF package")]
    WriteTuIndex(#[source] gimli::write::Error),
    #[error("Unit(s) {0:?} was referenced by executable but not found")]
    MissingReferencedUnit(Vec<DwarfObjectIdentifier>),
    #[error("No output object was created from inputs")]
    NoOutputObjectCreated,

    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ObjectRead(#[from] object::Error),
    #[error(transparent)]
    ObjectWrite(#[from] object::write::Error),
    #[error(transparent)]
    GimliRead(#[from] gimli::read::Error),
    #[error(transparent)]
    GimliWrite(#[from] gimli::write::Error),
}
