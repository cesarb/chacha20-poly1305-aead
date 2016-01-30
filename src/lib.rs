// Copyright 2016 chacha20-poly1305-aead Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A pure Rust implementation of the ChaCha20-Poly1305 AEAD from RFC 7539.
//!
//! An Authenticated Encryption with Associated Data (AEAD) mode
//! encrypts data and generates an authentication tag, or decrypts data
//! and verifies an authentication tag, as a single operation. The tag
//! can also validate additional authenticated data (AAD) which is not
//! included in the cyphertext, for instance a plaintext header.
//!
//! The ChaCha20-Poly1305 AEAD uses a 256-bit (32-byte) key, and a
//! 96-bit (12-byte) nonce. For each key, a given nonce should be used
//! only once, otherwise the encryption and authentication can be
//! broken. One way to prevent reuse is for the nonce to contain a
//! sequence number.
//!
//! The amount of data that can be encrypted in a single call is 2^32 - 1
//! blocks of 64 bytes, slightly less than 256 GiB.

#![warn(missing_docs)]

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", warn(clippy_pedantic))]

#![cfg_attr(all(feature = "bench", test), feature(test))]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd_opt", feature(cfg_target_feature))]

#[cfg(all(feature = "bench", test))]
extern crate test;

extern crate constant_time_eq;

mod as_bytes;

mod simdty;
mod simdint;
mod simdop;
mod simd_opt;
mod simd;

mod chacha20;
mod poly1305;
mod aead;

pub use aead::{DecryptError, decrypt, encrypt, encrypt_read};

/// Runs the self-test for ChaCha20, Poly1305, and the AEAD.
#[cold]
pub fn selftest() {
    chacha20::selftest();
    poly1305::selftest();
    aead::selftest::selftest();
}
