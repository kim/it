# it: zero-g git

_it_ aims to augment git with primitives to build integrated, cryptographically
verifiable collaboration workflows around source code. It maintains the
distributed property of git, not requiring a central server. _it_ is transport
agnostic, and permits data dissemination in client-server, federated, as well as
peer-to-peer network topologies.


## Status

_it_ is **experimental** software. Do not for anything serious.

That said, the [spec](./Documentation/spec.adoc) is thought of as being fairly
stable, in the sense that any amendments will consider backwards compatibility.

The source code in this repository has been developed exploratively, in order to
validate and refine the ideas laid out in above document. As such, it is
incomplete, may occasionally malfunction, and does not yet provide the fine bone
porcelain rendering it usable in anger. It's a prototype, if you wish.


## Usage

The _it_ implementation is written in Rust and can be installed from source
using [cargo](https://doc.rust-lang.org/cargo/):

    cargo install --git https://git.eagain.io/it

To get an overview, see the [getting started](./Documentation/getting-started.adoc)
document.


## License

GPL-2.0, see [COPYING](./COPYING)
