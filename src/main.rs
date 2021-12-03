use anyhow::Result;
use std::{io::stderr, path::PathBuf};
use structopt::StructOpt;
use tracing::trace;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_tree::HierarchicalLayer;

use thorin::package;

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

fn main() -> Result<()> {
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

    package(opt.inputs, opt.executables, opt.output)
}
