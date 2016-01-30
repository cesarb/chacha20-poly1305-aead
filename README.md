This is a pure Rust implementation of the ChaCha20-Poly1305 AEAD from
[RFC 7539].

[RFC 7539]: https://tools.ietf.org/html/rfc7539

## Design

There are two main designs for an encryption/decryption API: either
having one state/context struct with a method which is called repeatedly
to encrypt/decrypt the next fragment of data, or having a single
standalone function which is called once and does all the work in a
single call.

For authenticated encryption, it's important that on decryption no
output is produced until the authentication tag is verified. That
requires two passes over the data for decryption: the first pass
verifies the tag, and the second pass does the output. It would be
needlessly complex to implement this with a state/context struct, so
this crate uses a single function call to do the whole decryption. For
simmetry, the same design is used for the encryption function.

The base primitives (ChaCha20 and Poly1305) are not exposed separately,
since they are harder to use securely. This also allows their
implementation to be tuned to the combined use case; for instance, the
base primitives need no buffering.

## Limitations

The amount of data that can be encrypted in a single call is 2^32 - 1
blocks of 64 bytes, slightly less than 256 GiB. This limit could be
increased to 2^64 bytes, if necessary, by allowing the use of a shorter
nonce.

This crate does not attempt to clear potentially sensitive data from its
work memory (which includes the the stack and processor registers). To
do so correctly without a heavy performance penalty would require help
from the compiler. It's better to not attempt to do so than to present a
false assurance.

## SIMD optimization

This crate has experimental support for explicit SIMD optimizations. It
requires nightly Rust due to the use of unstable features.

The following cargo features enable the explicit SIMD optimization:

* `simd` enables the explicit use of SIMD vectors instead of a plain
  struct
* `simd_opt` additionally enables the use of SIMD shuffles to implement
  some of the rotates

While one might expect that each of these is faster than the previous
one, and that they are all faster than not enabling explicit SIMD
vectors, that's not always the case. It can vary depending on target
architecture and compiler options. If you need the extra speed from
these optimizations, benchmark each one (the `bench` feature enables
`cargo bench` in this crate, so you can use for instance `cargo bench
--features="bench simd_opt"`). They have currently been tuned for SSE2
(x86 and x86-64) and NEON (arm).

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
