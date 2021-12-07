use std::{
    borrow::Borrow,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use memmap2::Mmap;
use object::write::StreamingBuffer;
use structopt::StructOpt;
use thiserror::Error;
use tracing::trace;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;
use typed_arena::Arena;

#[derive(Debug, Error)]
enum Error {
    #[error("Failed to create output object `{1}`")]
    CreateOutputFile(#[source] std::io::Error, String),
    #[error("Failed to emit output object to buffer")]
    EmitOutputObject(#[source] object::write::Error),
    #[error("Failed to write output object to buffer")]
    WriteBuffer(#[source] std::io::Error),
    #[error("Failed to write output object to disk")]
    FlushBufferedWriter(#[source] std::io::Error),

    #[error(transparent)]
    Thorin(#[from] thorin::Error),
}

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

/// Returns `true` if the file type is a fifo.
#[cfg(not(target_family = "unix"))]
fn is_fifo(_: std::fs::FileType) -> bool {
    false
}

/// Returns `true` if the file type is a fifo.
#[cfg(target_family = "unix")]
fn is_fifo(file_type: std::fs::FileType) -> bool {
    use std::os::unix::fs::FileTypeExt;
    file_type.is_fifo()
}

/// Wrapper around output writer which handles differences between stdout, file and pipe outputs.
pub(crate) enum Output {
    Stdout(io::Stdout),
    File(File),
    Pipe(File),
}

impl Output {
    /// Create a `Output` from the input path (or "-" for stdout).
    pub(crate) fn new(path: &OsStr) -> io::Result<Self> {
        if path == "-" {
            return Ok(Output::Stdout(io::stdout()));
        }

        let file =
            OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
        if is_fifo(file.metadata()?.file_type()) {
            Ok(Output::File(file))
        } else {
            Ok(Output::Pipe(file))
        }
    }
}

impl io::Write for Output {
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Output::Stdout(stdout) => stdout.flush(),
            Output::Pipe(pipe) => pipe.flush(),
            Output::File(file) => file.flush(),
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Output::Stdout(stdout) => stdout.write(buf),
            Output::Pipe(pipe) => pipe.write(buf),
            Output::File(file) => file.write(buf),
        }
    }
}

fn main() -> Result<(), Error> {
    let subscriber = Registry::default().with(EnvFilter::from_env("RUST_DWP_LOG")).with(
        HierarchicalLayer::default()
            .with_writer(io::stderr)
            .with_indent_lines(true)
            .with_targets(true)
            .with_indent_amount(2),
    );
    tracing::subscriber::set_global_default(subscriber).expect("failed to set subscriber");

    let opt = Opt::from_args();
    trace!(?opt);

    let sess = Session::default();
    let mut package = thorin::DwarfPackage::new(&sess);

    for input in opt.inputs {
        package.add_input_object(&input).map_err(Error::Thorin)?;
    }

    if let Some(executables) = opt.executables {
        for executable in executables {
            // Failing to read the referenced object might be expected if the path referenced by
            // the executable isn't found but the referenced DWARF object is later found as an
            // input - calling `finish` will return an error in this case.
            package.add_executable(&executable, thorin::MissingReferencedObjectBehaviour::Skip)?;
        }
    }

    let output_stream = Output::new(opt.output.as_ref())
        .map_err(|e| Error::CreateOutputFile(e, opt.output.display().to_string()))?;
    let mut output_stream = StreamingBuffer::new(BufWriter::new(output_stream));
    package
        .finish()
        .map_err(Error::Thorin)?
        .emit(&mut output_stream)
        .map_err(Error::EmitOutputObject)?;
    output_stream.result().map_err(Error::WriteBuffer)?;
    output_stream.into_inner().flush().map_err(Error::FlushBufferedWriter)
}
