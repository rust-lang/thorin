# `thorin`
`thorin` is an DWARF packaging utility for creating DWARF packages (`*.dwp` files) out of input
DWARF objects (`*.dwo` files; or `*.o` files with `.dwo` sections), supporting both the pre-standard
GNU extension format for DWARF packages and the standardized format introduced in DWARF 5.

`thorin` was written as part of the implementation of Split DWARF in `rustc`. A Rust implementation
of a DWARF packaging utility is easier to integrate into the compiler and can support features like
loading dwarf objects from archive files (or rustc's rlibs) which are helpful in supporting
cross-crate Split DWARF packaging in `rustc`.

See the README documents of the [`thorin` crate](thorin/README.md) and the
[`thorin-bin` crate](thorin-bin/README.md) for usage details of the library and binary interfaces
respectively.

## Contributing to `thorin`
If you want help or mentorship, reach out to us in a GitHub issue, or ask `davidtwco` or in
`#t-compiler` on the [Rust Zulip instance](https://rust-lang.zulipchat.com/).

`thorin` should always build on stable `rustc`. To build `thorin`:

```shell-session
$ cargo build
```

To run the tests, first install the relevant dependencies:

```shell-session
$ apt install --no-install-recommends --yes llvm-15 llvm-15-tools
$ pip install lit
```

Next, run the `lit` testsuite (replacing `/path/to/llvm/bin` with the correct path to your LLVM
installation, if required):

```shell-session
$ cargo build # in debug mode..
$ lit -v --path "$PWD/target/debug/:/path/to/llvm/bin/" ./tests
$ cargo build --release # ..or in release mode
$ lit -v --path "$PWD/target/release/:/path/to/llvm/bin/" ./tests
```

We use `rustfmt` to automatically format and style all of our code. To install and use `rustfmt`:

```shell-session
$ rustup component add rustfmt
$ cargo fmt
```

### Filing an issue
Think you've found a bug? File an issue! To help us understand and reproduce the
issue, provide us with:

* The (preferably minimal) test case
* Steps to reproduce the issue using the test case
* The expected result of following those steps
* The actual result of following those steps

Definitely file an issue if you see an unexpected panic originating from within `thorin`!
`thorin` should never panic unless it is explicitly documented to panic in the specific
circumstances provided.

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
<code>thorin</code> is authored by <a href="https://davidtw.co">David Wood</a>.
<code>thorin</code> is maintained by the
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
