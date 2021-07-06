## Tryptich Log Sized Ring Signatures for Rust

This is a Rust Crate implementing the Tryptich Ring Singature Protocol ([IACR Preprint](https://eprint.iacr.org/2020/018.pdf)) presently being deployed into Monero.

There are two crates here, `libtryptich` is the library crate and `testtryptich` is an example demo crate using the library.

Dalek Cryptography's Rust Crate for the Risretto Curve provides the backend functions.