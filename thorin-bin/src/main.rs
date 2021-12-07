use memmap2::Mmap;
use std::borrow::Borrow;
use std::fs::File;
use std::path::Path;
use std::{io::stderr, path::PathBuf};
use structopt::StructOpt;
use tracing::trace;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;
use typed_arena::Arena;

#[derive(Debug, StructOpt)]
#[structopt(name = "thorin", about = "merge dwarf objects into dwarf packages")]
struct Opt {
    /// Specify path to input dwarf objects and packages
    #[structopt(parse(from_os_str))]
    inputs: Vec<PathBuf>,
    /// Specify path to executables to read list of dwarf objects from
    #[structopt(short = "e", long = "exec", parse(from_os_str))]
    executables: Option<Vec<PathBuf>>,
    /// Specify path to write the dwarf package to
    #[structopt(short = "o", long = "output", parse(from_os_str), default_value = "-")]
    output: PathBuf,
}

/// Implementation of `thorin::Session` using `typed_arena` and `memmap2`.
#[derive(Default)]
struct Session<Relocations> {
    arena_data: Arena<Vec<u8>>,
    arena_mmap: Arena<Mmap>,
    arena_relocations: Arena<Relocations>,
}

impl<Relocations> Session<Relocations> {
    fn alloc_mmap<'arena>(&'arena self, data: Mmap) -> &'arena Mmap {
        (*self.arena_mmap.alloc(data)).borrow()
    }
}

impl<Relocations> thorin::Session<Relocations> for Session<Relocations> {
    fn alloc_data<'arena>(&'arena self, data: Vec<u8>) -> &'arena [u8] {
        (*self.arena_data.alloc(data)).borrow()
    }

    fn alloc_relocation<'arena>(&'arena self, data: Relocations) -> &'arena Relocations {
        (*self.arena_relocations.alloc(data)).borrow()
    }

    fn read_input<'arena>(&'arena self, path: &Path) -> std::io::Result<&'arena [u8]> {
        let file = File::open(&path)?;
        let mmap = (unsafe { Mmap::map(&file) })?;
        Ok(self.alloc_mmap(mmap))
    }
}

fn main() -> Result<(), thorin::DwpError> {
    let subscriber = Registry::default().with(EnvFilter::from_env("RUST_DWP_LOG")).with(
        HierarchicalLayer::default()
            .with_writer(stderr)
            .with_indent_lines(true)
            .with_targets(true)
            .with_indent_amount(2),
    );
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");

    let opt = Opt::from_args();
    trace!(?opt);

    let sess = Session::default();
    thorin::package(&sess, opt.inputs, opt.executables, opt.output)
}
