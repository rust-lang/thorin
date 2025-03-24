# `thorin`
`thorin` is an DWARF packaging utility for creating DWARF packages (`*.dwp` files) out of input
DWARF objects (`*.dwo` files; or `*.o` files with `.dwo` sections), supporting both the pre-standard
GNU extension format for DWARF packages and the standardized format introduced in DWARF 5.

`thorin` was written as part of the implementation of Split DWARF in `rustc`. A Rust implementation
of a DWARF packaging utility is easier to integrate into the compiler and can support features like
loading dwarf objects from archive files (or rustc's rlibs) which are helpful in supporting
cross-crate Split DWARF packaging in `rustc`.

## Usage
`thorin` can read input DWARF objects from executables or can package arbitrary input dwarf
objects (including DWARF objects in archive files, such as Rust rlibs)! Install `thorin` using
`cargo`:

```shell-session
$ cargo install thorin-dwp-bin
$ thorin --help
thorin 0.9.0
merge dwarf objects into dwarf packages

USAGE:
    thorin [OPTIONS] [--] [inputs]...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -e, --exec <executables>...    Specify path to executables to read list of dwarf objects from
    -o, --output <output>          Specify path to write the dwarf package to [default: -]

ARGS:
    <inputs>...    Specify path to input dwarf objects and packages
```

If the input objects are of DWARF version 5 or greater, then the output package will be in DWARF 5
format. For version 4 and below, the GNU Extension format will be used for the output package.

## Stability
`thorin`'s command-line interface is intended to be stable and have limited breaking changes.

<br>

#### Name
<sup>
<code>thorin</code> is named after <i>Thorin Oakenshield</i> from <i>The Hobbit</i>, as Thorin is
a dwarf who leads other dwarves. <code>thorin</code> uses the <code>gimli</code> library
(named after a dwarf from <i>Lord of the Rings</i>) to read <i>DWARF</i> format debug information,
the name of which is a medieval fantasy complement to <i>ELF</i>, the file format for executables
and object files.
</sup>

<br>

<sub>
You could also call this project <code>rust-dwp</code>, if you'd prefer that.
</sub>

<br>

#### Author and acknowledgements
<sup>
<code>thorin</code> is authored by <a href="https://davidtw.co">David Wood</a> of <i>Huawei
Technologies Research & Development (UK) Ltd</i>. <code>thorin</code> is maintained by the
<a href="https://rust-lang.org/governance/teams/compiler">Rust Compiler Team</a>.
</sup>

<br>

<sub>
In addition, thanks to the authors of <code>object</code> and <code>gimli</code>, on which this
utility depends heavily; and to <a href="https://github.com/philipc">Philip Craig</a> for advice
and reviews during initial implementation of <code>thorin</code>.
</sub>

<br>

#### License
<sup>
Licensed under either of <a href="https://www.apache.org/licenses/LICENSE-2.0">Apache License,
Version 2.0</a> or <a href="https://opensource.org/licenses/MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
</sub>

<br>

#### Code of conduct
<sup>
When contributing or interacting with this project, we ask abide the
<a href="https://www.rust-lang.org/en-US/conduct.html">Rust Code of Conduct</a> and ask that you do
too.
</sup>
