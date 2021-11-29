/// Helper trait for types that have a corresponding `gimli::SectionId`.
pub(crate) trait HasGimliId {
    /// Return the corresponding `gimli::SectionId`.
    fn gimli_id() -> gimli::SectionId;
}

macro_rules! define_section_markers {
    ( $( $name:ident ),+ ) => {
        $(
            /// Marker type implementing `HasGimliId`, corresponds to `gimli::SectionId::$name`.
            /// Intended for use with `LazySectionId`.
            #[derive(Default)]
            pub(crate) struct $name;

            impl HasGimliId for $name {
                fn gimli_id() -> gimli::SectionId { gimli::SectionId::$name }
            }
        )+
    }
}

define_section_markers!(DebugInfo, DebugAbbrev, DebugStr, DebugTypes, DebugLine, DebugLoc);
define_section_markers!(DebugLocLists, DebugRngLists, DebugStrOffsets, DebugMacinfo, DebugMacro);
define_section_markers!(DebugCuIndex, DebugTuIndex);
