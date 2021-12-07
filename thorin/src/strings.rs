use std::collections::HashMap;

use gimli::{
    write::{EndianVec, Result, Writer},
    DebugStrOffset,
};
use indexmap::IndexSet;
use object::write::Object;

use crate::{marker::DebugStr, util::LazySectionId};

/// New-type'd index from `IndexVec` of strings inserted into the `.debug_str` section.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DwpStringId(usize);

/// DWARF packages need to merge the `.debug_str` sections of input DWARF objects.
/// `.debug_str_offsets` sections then need to be rebuilt with offsets into the new merged
/// `.debug_str` section and then concatenated (indices into each dwarf object's offset list will
/// therefore still refer to the same string).
///
/// Gimli's `StringTable` produces a `.debug_str` section with a single `.debug_str_offsets`
/// section, but `DwpStringTable` accumulates a single `.debug_str` section and can be used to
/// produce multiple `.debug_str_offsets` sections (which will be concatenated) which all offset
/// into the same `.debug_str`.
pub(crate) struct DwpStringTable<E: gimli::Endianity> {
    debug_str: gimli::write::DebugStr<EndianVec<E>>,
    strings: IndexSet<Vec<u8>>,
    offsets: HashMap<DwpStringId, DebugStrOffset>,
}

impl<E: gimli::Endianity> DwpStringTable<E> {
    /// Create a new `DwpStringTable` with a given endianity.
    pub(crate) fn new(endianness: E) -> Self {
        Self {
            debug_str: gimli::write::DebugStr(EndianVec::new(endianness)),
            strings: IndexSet::new(),
            offsets: HashMap::new(),
        }
    }

    /// Insert a string into the string table and return its offset in the table. If the string is
    /// already in the table, returns its offset.
    pub(crate) fn get_or_insert<T: Into<Vec<u8>>>(&mut self, bytes: T) -> Result<DebugStrOffset> {
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
    /// section in the object (if there was a `.debug_str` section to write at all).
    pub(crate) fn write<'output>(
        self,
        debug_str: &mut LazySectionId<DebugStr>,
        obj: &mut Object<'output>,
    ) -> Option<u64> {
        let data = self.debug_str.0.slice();
        if !data.is_empty() {
            // FIXME: what is the correct way to determine this alignment
            let id = debug_str.get(obj);
            Some(obj.append_section_data(id, data, 1))
        } else {
            None
        }
    }
}
