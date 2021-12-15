use std::fmt;

use gimli::{
    write::{EndianVec, Writer},
    Encoding,
};
use tracing::{debug, trace};

use crate::{
    error::{Error, Result},
    ext::PackageFormatExt,
    package::{DebugTypeSignature, DwoId},
};

/// Helper trait for types that can be used in creating the `.debug_{cu,tu}_index` hash table.
pub(crate) trait Bucketable {
    fn index(&self) -> u64;
}

/// Returns a hash table computed for `elements`. Used in the `.debug_{cu,tu}_index` sections.
#[tracing::instrument(level = "trace", skip_all)]
fn bucket<B: Bucketable + fmt::Debug>(elements: &[B]) -> Vec<u32> {
    let unit_count: u32 = elements.len().try_into().expect("unit count too big for u32");
    let num_buckets = if elements.len() < 2 { 2 } else { (3 * unit_count / 2).next_power_of_two() };
    let mask: u64 = num_buckets as u64 - 1;
    trace!(?mask);

    let mut buckets = vec![0u32; num_buckets as usize];
    trace!(?buckets);
    for (elem, i) in elements.iter().zip(0u32..) {
        trace!(?i, ?elem);
        let s = elem.index();
        let mut h = s & mask;
        let hp = ((s >> 32) & mask) | 1;
        trace!(?s, ?h, ?hp);

        while buckets[h as usize] > 0 {
            assert!(elements[(buckets[h as usize] - 1) as usize].index() != elem.index());
            h = (h + hp) & mask;
            trace!(?h);
        }

        buckets[h as usize] = i + 1;
        trace!(?buckets);
    }

    buckets
}

/// New-type'd offset into a section of a compilation/type unit's contribution.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct ContributionOffset(pub(crate) u64);

impl fmt::Debug for ContributionOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContributionOffset({:#x})", self.0)
    }
}

pub(crate) trait IndexEntry: Bucketable {
    /// Return the encoding of the input object which contributed this entry.
    fn encoding(&self) -> Encoding;

    /// Return the number of columns in `.debug_{cu,tu}_index` required by this entry.
    fn number_of_columns(&self) -> u32;

    /// Return the signature of the entry (`DwoId` or `DebugTypeSignature`).
    fn signature(&self) -> u64;

    /// Write the header for the index entry (e.g. `gimli::DW_SECT_INFO` constants)
    ///
    /// Only uses the entry to know which columns exist (invariant: every entry has the same
    /// number of columns).
    fn write_header<Endian: gimli::Endianity>(&self, out: &mut EndianVec<Endian>) -> Result<()>;

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
pub(crate) struct Contribution {
    /// Offset of this contribution into its containing section.
    pub(crate) offset: ContributionOffset,
    /// Size of this contribution in its containing section.
    pub(crate) size: ContributionSize,
}

/// Entry into the `.debug_tu_index` section.
///
/// Contributions from `.debug_loclists.dwo` and `.debug_rnglists.dwo` from type units aren't
/// defined in the DWARF 5 specification but are tested by `llvm-dwp`'s test suite.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TuIndexEntry {
    pub(crate) encoding: Encoding,
    pub(crate) type_signature: DebugTypeSignature,
    pub(crate) debug_info_or_types: Contribution,
    pub(crate) debug_abbrev: Contribution,
    pub(crate) debug_line: Option<Contribution>,
    pub(crate) debug_loclists: Option<Contribution>,
    pub(crate) debug_rnglists: Option<Contribution>,
    pub(crate) debug_str_offsets: Option<Contribution>,
}

impl IndexEntry for TuIndexEntry {
    fn encoding(&self) -> Encoding {
        self.encoding
    }

    fn number_of_columns(&self) -> u32 {
        2 /* info/types and abbrev are required columns */
        + self.debug_line.map_or(0, |_| 1)
        + self.debug_loclists.map_or(0, |_| 1)
        + self.debug_rnglists.map_or(0, |_| 1)
        + self.debug_str_offsets.map_or(0, |_| 1)
    }

    fn signature(&self) -> u64 {
        self.type_signature.0
    }

    #[tracing::instrument(level = "trace", skip(out))]
    fn write_header<Endian: gimli::Endianity>(&self, out: &mut EndianVec<Endian>) -> Result<()> {
        if self.encoding.is_gnu_extension_dwarf_package_format() {
            out.write_u32(gimli::DW_SECT_V2_TYPES.0)?;
            out.write_u32(gimli::DW_SECT_V2_ABBREV.0)?;
            if self.debug_line.is_some() {
                out.write_u32(gimli::DW_SECT_V2_LINE.0)?;
            }
            if self.debug_str_offsets.is_some() {
                out.write_u32(gimli::DW_SECT_V2_STR_OFFSETS.0)?;
            }
        } else {
            out.write_u32(gimli::DW_SECT_INFO.0)?;
            out.write_u32(gimli::DW_SECT_ABBREV.0)?;
            if self.debug_line.is_some() {
                out.write_u32(gimli::DW_SECT_LINE.0)?;
            }
            if self.debug_loclists.is_some() {
                out.write_u32(gimli::DW_SECT_LOCLISTS.0)?;
            }
            if self.debug_rnglists.is_some() {
                out.write_u32(gimli::DW_SECT_RNGLISTS.0)?;
            }
            if self.debug_str_offsets.is_some() {
                out.write_u32(gimli::DW_SECT_STR_OFFSETS.0)?;
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(out, proj))]
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
        if let Some(debug_loclists) = self.debug_loclists {
            out.write_u32(proj(debug_loclists))?;
        }
        if let Some(debug_rnglists) = self.debug_rnglists {
            out.write_u32(proj(debug_rnglists))?;
        }
        if let Some(debug_str_offsets) = self.debug_str_offsets {
            out.write_u32(proj(debug_str_offsets))?;
        }
        Ok(())
    }
}

/// Entry into the `.debug_cu_index` section.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CuIndexEntry {
    pub(crate) encoding: Encoding,
    pub(crate) dwo_id: DwoId,
    pub(crate) debug_info: Contribution,
    pub(crate) debug_abbrev: Contribution,
    pub(crate) debug_line: Option<Contribution>,
    pub(crate) debug_loc: Option<Contribution>,
    pub(crate) debug_loclists: Option<Contribution>,
    pub(crate) debug_rnglists: Option<Contribution>,
    pub(crate) debug_str_offsets: Option<Contribution>,
    pub(crate) debug_macinfo: Option<Contribution>,
    pub(crate) debug_macro: Option<Contribution>,
}

impl IndexEntry for CuIndexEntry {
    fn encoding(&self) -> Encoding {
        self.encoding
    }

    fn number_of_columns(&self) -> u32 {
        if self.encoding.is_gnu_extension_dwarf_package_format() {
            2 /* info and abbrev are required columns */
            + self.debug_line.map_or(0, |_| 1)
            + self.debug_loc.map_or(0, |_| 1)
            + self.debug_str_offsets.map_or(0, |_| 1)
            + self.debug_macinfo.map_or(0, |_| 1)
            + self.debug_macro.map_or(0, |_| 1)
        } else {
            2 /* info and abbrev are required columns */
            + self.debug_line.map_or(0, |_| 1)
            + self.debug_loclists.map_or(0, |_| 1)
            + self.debug_rnglists.map_or(0, |_| 1)
            + self.debug_str_offsets.map_or(0, |_| 1)
            + self.debug_macro.map_or(0, |_| 1)
        }
    }

    fn signature(&self) -> u64 {
        self.dwo_id.0
    }

    fn write_header<Endian: gimli::Endianity>(&self, out: &mut EndianVec<Endian>) -> Result<()> {
        if self.encoding.is_gnu_extension_dwarf_package_format() {
            out.write_u32(gimli::DW_SECT_V2_INFO.0)?;
            out.write_u32(gimli::DW_SECT_V2_ABBREV.0)?;
            if self.debug_line.is_some() {
                out.write_u32(gimli::DW_SECT_V2_LINE.0)?;
            }
            if self.debug_loc.is_some() {
                out.write_u32(gimli::DW_SECT_V2_LOC.0)?;
            }
            if self.debug_str_offsets.is_some() {
                out.write_u32(gimli::DW_SECT_V2_STR_OFFSETS.0)?;
            }
            if self.debug_macinfo.is_some() {
                out.write_u32(gimli::DW_SECT_V2_MACINFO.0)?;
            }
            if self.debug_macro.is_some() {
                out.write_u32(gimli::DW_SECT_V2_MACRO.0)?;
            }
        } else {
            out.write_u32(gimli::DW_SECT_INFO.0)?;
            out.write_u32(gimli::DW_SECT_ABBREV.0)?;
            if self.debug_line.is_some() {
                out.write_u32(gimli::DW_SECT_LINE.0)?;
            }
            if self.debug_loclists.is_some() {
                out.write_u32(gimli::DW_SECT_LOCLISTS.0)?;
            }
            if self.debug_rnglists.is_some() {
                out.write_u32(gimli::DW_SECT_RNGLISTS.0)?;
            }
            if self.debug_str_offsets.is_some() {
                out.write_u32(gimli::DW_SECT_STR_OFFSETS.0)?;
            }
            if self.debug_macro.is_some() {
                out.write_u32(gimli::DW_SECT_MACRO.0)?;
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(out, proj))]
    fn write_contribution<Endian, Proj>(
        &self,
        out: &mut EndianVec<Endian>,
        proj: Proj,
    ) -> Result<()>
    where
        Endian: gimli::Endianity,
        Proj: Fn(Contribution) -> u32,
    {
        if self.encoding.is_gnu_extension_dwarf_package_format() {
            out.write_u32(proj(self.debug_info))?;
            out.write_u32(proj(self.debug_abbrev))?;
            if let Some(debug_line) = self.debug_line {
                out.write_u32(proj(debug_line))?;
            }
            if let Some(debug_loc) = self.debug_loc {
                out.write_u32(proj(debug_loc))?;
            }
            if let Some(debug_str_offsets) = self.debug_str_offsets {
                out.write_u32(proj(debug_str_offsets))?;
            }
            if let Some(debug_macinfo) = self.debug_macinfo {
                out.write_u32(proj(debug_macinfo))?;
            }
            if let Some(debug_macro) = self.debug_macro {
                out.write_u32(proj(debug_macro))?;
            }
        } else {
            out.write_u32(proj(self.debug_info))?;
            out.write_u32(proj(self.debug_abbrev))?;
            if let Some(debug_line) = self.debug_line {
                out.write_u32(proj(debug_line))?;
            }
            if let Some(debug_loclists) = self.debug_loclists {
                out.write_u32(proj(debug_loclists))?;
            }
            if let Some(debug_rnglists) = self.debug_rnglists {
                out.write_u32(proj(debug_rnglists))?;
            }
            if let Some(debug_str_offsets) = self.debug_str_offsets {
                out.write_u32(proj(debug_str_offsets))?;
            }
            if let Some(debug_macro) = self.debug_macro {
                out.write_u32(proj(debug_macro))?;
            }
        }

        Ok(())
    }
}

pub(crate) trait IndexCollection<Entry: IndexEntry> {
    /// Write `.debug_{cu,tu}_index` to the output object.
    fn write_index<'output, Endian: gimli::Endianity>(
        &self,
        endianness: Endian,
    ) -> Result<EndianVec<Endian>>;
}

impl<Entry: IndexEntry + fmt::Debug> IndexCollection<Entry> for Vec<Entry> {
    #[tracing::instrument(level = "trace")]
    fn write_index<'output, Endian: gimli::Endianity>(
        &self,
        endianness: Endian,
    ) -> Result<EndianVec<Endian>> {
        let mut out = EndianVec::new(endianness);

        if self.len() == 0 {
            return Ok(out);
        }

        let buckets = bucket(self);
        debug!(?buckets);

        let encoding = self[0].encoding();
        if !self.iter().all(|e| e.encoding() == encoding) {
            return Err(Error::MixedInputEncodings);
        }
        debug!(?encoding);

        let num_columns = self[0].number_of_columns();
        assert!(self.iter().all(|e| e.number_of_columns() == num_columns));
        debug!(?num_columns);

        // Write header..
        if encoding.is_gnu_extension_dwarf_package_format() {
            // GNU Extension
            out.write_u32(2)?;
        } else {
            // DWARF 5
            out.write_u16(5)?;
            // Reserved padding
            out.write_u16(0)?;
        }

        // Columns (e.g. info, abbrev, loc, etc.)
        out.write_u32(num_columns)?;
        // Number of units
        out.write_u32(self.len().try_into().expect("number of units larger than u32"))?;
        // Number of buckets
        out.write_u32(buckets.len().try_into().expect("number of buckets larger than u32"))?;

        // Write signatures..
        for i in &buckets {
            if *i > 0 {
                out.write_u64(self[(*i - 1) as usize].signature())?;
            } else {
                out.write_u64(0)?;
            }
        }

        // Write indices..
        for i in &buckets {
            out.write_u32(*i)?;
        }

        // Write column headers..
        self[0].write_header(&mut out)?;

        // Write offsets..
        let write_offset = |contrib: Contribution| {
            contrib.offset.0.try_into().expect("contribution offset larger than u32")
        };
        for entry in self {
            entry.write_contribution(&mut out, write_offset)?;
        }

        // Write sizes..
        let write_size = |contrib: Contribution| {
            contrib.size.try_into().expect("contribution size larger than u32")
        };
        for entry in self {
            entry.write_contribution(&mut out, write_size)?;
        }

        Ok(out)
    }
}
