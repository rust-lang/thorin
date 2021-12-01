use thiserror::Error;

use crate::package::DwarfObjectIdentifier;

/// Diagnostics (and contexts) emitted during DWARF packaging.
#[derive(Debug, Error)]
pub(crate) enum DwpError {
    #[error("Failed to open object file")]
    OpenObjectFile,
    #[error("Failed to mmap object file")]
    MmapObjectFile,
    #[error("Failed to parse kind of input file")]
    ParseFileKind,
    #[error("Failed to parse object file")]
    ParseObjectFile,
    #[error("Failed to parse archive file")]
    ParseArchiveFile,
    #[error("Failed to parse archive member")]
    ParseArchiveMember,
    #[error("Section without name at offset 0x{0:08x}")]
    NamelessSection(usize),
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
    #[error("Failed finding DWARF objects in executable `{0}`")]
    FindingDwarfObjectsInExecutable(String),
    #[error("Failed to load input DWARF object `{0}`")]
    LoadInputDwarfObject(String),
    #[error("Input DWARF object missing required section `{0}`")]
    MissingRequiredSection(String),
    #[error("Failed to parse unit header")]
    ParseUnitHeader,
    #[error("Failed to parse unit")]
    ParseUnit,
    #[error("Failed to concatenate `{0}` section from input DWARF object")]
    ConcatenatingSection(&'static str),
    #[error("Failed to remap `.debug_str_offsets.dwo` section")]
    AddingStrOffsets,
    #[error("Failed to read header of `.debug_str_offsets.dwo` section")]
    StrOffsetsMissingHeader,
    #[error("Failed to read offset at index {0} of `.debug_str_offsets.dwo` section")]
    OffsetAtIndex(u64),
    #[error("Failed to read string at offset {0:08x} of `.debug_str.dwo` section")]
    StrAtOffset(usize),
    #[error("Failed to write string to in-progress `.debug_str.dwo` section")]
    WritingStrToStringTable,
    #[error("Failed to parse `.debug_cu_index` of input DWARF package")]
    LoadCuIndex,
    #[error("Failed to parse `.debug_tu_index` of input DWARF package")]
    LoadTuIndex,
    #[error("Unit 0x{0:08x} from input DWARF package is not in its index")]
    UnitNotInIndex(u64),
    #[error("Row {0} found in index's hash table not present in index")]
    RowNotInIndex(u32),
    #[error("Section not found in unit's row in index")]
    SectionNotInRow,
    #[error("Failed to adjust contribution for section `{0}`")]
    AdjustingContribution(&'static str),
    #[error("Unit `{0}` in input DWARF object with no data")]
    EmptyUnit(u64),
    #[error("Failed to add units from section `{0}`")]
    AddingUnitsFromSection(&'static str),
    #[error("Failed adding input DWARF object `{0}` to DWARF package")]
    AddingDwarfObjectToOutput(String),
    #[error("Failed to write `.debug_cu_index` of output DWARF package")]
    WriteCuIndex,
    #[error("Failed to write `.debug_tu_index` of output DWARF package")]
    WriteTuIndex,
    #[error("Failed to create output object `{0}`")]
    CreateOutputFile(String),
    #[error("Unit(s) {0:?} was referenced by executable but not found")]
    MissingReferencedUnit(Vec<DwarfObjectIdentifier>),
    #[error("Failed to write in-memory output object to streaming buffer")]
    WriteInMemoryRepresentation,
    #[error("Failed to write output object to buffer")]
    WriteBuffer,
    #[error("Failed to write output object to disk")]
    FlushBufferedWriter,
}
