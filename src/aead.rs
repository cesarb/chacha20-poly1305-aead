// Copyright 2016 chacha20-poly1305-aead Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, ErrorKind, Read, Write};

use as_bytes::AsBytes;
use chacha20::ChaCha20;
use constant_time_eq::constant_time_eq;
use poly1305::Poly1305;
use simd::u32x4;

const CHACHA20_COUNTER_OVERFLOW: u64 = ((1 << 32) - 1) * 64;

/// Encrypts a byte slice and returns the authentication tag.
///
/// # Example
///
/// ```
/// use chacha20_poly1305_aead::encrypt;
///
/// let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
///            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
/// let nonce = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let aad = [1, 2, 3, 4];
///
/// let plaintext = b"hello, world";
///
/// // Vec implements the Write trait
/// let mut ciphertext = Vec::with_capacity(plaintext.len());
///
/// let tag = encrypt(&key, &nonce, &aad, plaintext, &mut ciphertext).unwrap();
///
/// assert_eq!(ciphertext, [0xfc, 0x5a, 0x17, 0x82,
///     0xab, 0xcf, 0xbc, 0x5d, 0x18, 0x29, 0xbf, 0x97]);
/// assert_eq!(tag, [0xdb, 0xb7, 0x0d, 0xda, 0xbd, 0xfa, 0x8c, 0xa5,
///                  0x60, 0xa2, 0x30, 0x3d, 0xe6, 0x07, 0x92, 0x10]);
/// ```
pub fn encrypt<W: Write>(key: &[u8], nonce: &[u8],
                         aad: &[u8], mut input: &[u8],
                         output: &mut W) -> io::Result<[u8; 16]> {
    encrypt_read(key, nonce, aad, &mut input, output)
}

/// Encrypts bytes from a reader and returns the authentication tag.
///
/// This function is identical to the `encrypt` function, the only
/// difference being that its input comes from a reader instead of a
/// byte slice.
pub fn encrypt_read<R: Read, W: Write>(key: &[u8], nonce: &[u8],
                                       aad: &[u8], input: &mut R,
                                       output: &mut W) -> io::Result<[u8; 16]> {
    let mut chacha20 = ChaCha20::new(key, nonce);
    let mut poly1305 = Poly1305::new(&chacha20.next().as_bytes()[..32]);

    let aad_len = aad.len() as u64;
    let mut input_len = 0;

    poly1305.padded_blocks(aad);

    let mut buf = [u32x4::default(); 4];
    loop {
        let read = try!(read_all(input, buf.as_mut_bytes()));
        if read == 0 { break; }

        input_len += read as u64;
        if input_len >= CHACHA20_COUNTER_OVERFLOW {
            return Err(io::Error::new(ErrorKind::WriteZero,
                                      "counter overflow"));
        }

        let block = chacha20.next();
        buf[0] = buf[0] ^ block[0];
        buf[1] = buf[1] ^ block[1];
        buf[2] = buf[2] ^ block[2];
        buf[3] = buf[3] ^ block[3];

        poly1305.padded_blocks(&buf.as_bytes()[..read]);
        try!(output.write_all(&buf.as_bytes()[..read]));
    }

    poly1305.block([aad_len.to_le(), input_len.to_le()].as_bytes());

    let mut tag = [0; 16];
    tag.clone_from_slice(poly1305.tag().as_bytes());
    Ok(tag)
}

/// Verifies the authentication tag and decrypts a byte slice.
///
/// If the tag does not match, this function produces no output and
/// returns `Err(DecryptError::TagMismatch)`.
///
/// # Example
///
/// ```
/// # use chacha20_poly1305_aead::DecryptError;
/// # fn example() -> Result<(), DecryptError> {
/// use chacha20_poly1305_aead::decrypt;
///
/// let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
///            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
/// let nonce = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let aad = [1, 2, 3, 4];
///
/// let ciphertext = [0xfc, 0x5a, 0x17, 0x82, 0xab, 0xcf, 0xbc, 0x5d,
///                   0x18, 0x29, 0xbf, 0x97];
/// let tag = [0xdb, 0xb7, 0x0d, 0xda, 0xbd, 0xfa, 0x8c, 0xa5,
///            0x60, 0xa2, 0x30, 0x3d, 0xe6, 0x07, 0x92, 0x10];
///
/// // Vec implements the Write trait
/// let mut plaintext = Vec::with_capacity(ciphertext.len());
///
/// try!(decrypt(&key, &nonce, &aad, &ciphertext, &tag, &mut plaintext));
///
/// assert_eq!(plaintext, b"hello, world");
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
pub fn decrypt<W: Write>(key: &[u8], nonce: &[u8],
                         aad: &[u8], mut input: &[u8], tag: &[u8],
                         output: &mut W) -> Result<(), DecryptError> {
    let mut chacha20 = ChaCha20::new(key, nonce);
    let mut poly1305 = Poly1305::new(&chacha20.next().as_bytes()[..32]);

    let aad_len = aad.len() as u64;
    let input_len = input.len() as u64;
    assert!(tag.len() == 16);

    if input_len >= CHACHA20_COUNTER_OVERFLOW {
        return Err(io::Error::new(ErrorKind::WriteZero,
                                  "counter overflow").into());
    }

    poly1305.padded_blocks(aad);
    poly1305.padded_blocks(input);
    poly1305.block([aad_len.to_le(), input_len.to_le()].as_bytes());

    if !constant_time_eq(poly1305.tag().as_bytes(), tag) {
        return Err(DecryptError::TagMismatch);
    }

    let mut buf = [u32x4::default(); 4];
    loop {
        let read = try!(read_all(&mut input, buf.as_mut_bytes()));
        if read == 0 { break; }

        let block = chacha20.next();
        buf[0] = buf[0] ^ block[0];
        buf[1] = buf[1] ^ block[1];
        buf[2] = buf[2] ^ block[2];
        buf[3] = buf[3] ^ block[3];

        try!(output.write_all(&buf.as_bytes()[..read]));
    }

    Ok(())
}

fn read_all<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> io::Result<usize> {
    let mut read = 0;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => { read += n; let tmp = buf; buf = &mut tmp[n..]; }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(read)
}

/// Error returned from the `decrypt` function.
#[derive(Debug)]
pub enum DecryptError {
    /// The calculated Poly1305 tag did not match the given tag.
    TagMismatch,

    /// There was an error writing the output.
    IoError(io::Error),
}

impl Display for DecryptError {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match *self {
            DecryptError::TagMismatch => fmt.write_str(self.description()),
            DecryptError::IoError(ref e) => e.fmt(fmt),
        }
    }
}

impl Error for DecryptError {
    fn description(&self) -> &str {
        match *self {
            DecryptError::TagMismatch => "authentication tag mismatch",
            DecryptError::IoError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            DecryptError::TagMismatch => None,
            DecryptError::IoError(ref e) => Some(e),
        }
    }
}

impl From<io::Error> for DecryptError {
    fn from(error: io::Error) -> Self {
        DecryptError::IoError(error)
    }
}

pub mod selftest {
    use super::*;

    static PLAINTEXT: &'static [u8] = b"\
        Ladies and Gentlemen of the class of '99: If I could offer you o\
        nly one tip for the future, sunscreen would be it.";

    static AAD: &'static [u8] = &[0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];

    static KEY: &'static [u8] = &[
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f];

    static NONCE: &'static [u8] = &[0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];

    static CIPHERTEXT: &'static [u8] = &[
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16];

    static TAG: &'static [u8] = &[
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91];

    #[cold]
    pub fn selftest() {
        selftest_encrypt();
        selftest_decrypt();
    }

    #[cold]
    pub fn selftest_encrypt() {
        selftest_encrypt_noinline(KEY, NONCE, AAD, PLAINTEXT, CIPHERTEXT, TAG);
    }

    #[cold]
    pub fn selftest_decrypt() {
        selftest_decrypt_noinline(KEY, NONCE, AAD, CIPHERTEXT, TAG, PLAINTEXT)
            .expect("selftest failure");

        let err = selftest_decrypt_noinline(KEY, NONCE, AAD, CIPHERTEXT,
                                            &[0; 16], &[]).unwrap_err();
        match err {
            DecryptError::TagMismatch => {}
            _ => panic!("selftest failure")
        }
    }

    #[inline(never)]
    #[cold]
    fn selftest_encrypt_noinline(key: &[u8], nonce: &[u8],
                                 aad: &[u8], input: &[u8],
                                 expected: &[u8], expected_tag: &[u8]) {
        let mut output = Vec::with_capacity(input.len());
        let tag = encrypt(key, nonce, aad, input, &mut output)
            .expect("selftest failure");

        assert_eq!(&output[..], expected);
        assert_eq!(tag, expected_tag);
    }

    #[inline(never)]
    #[cold]
    fn selftest_decrypt_noinline(key: &[u8], nonce: &[u8],
                                 aad: &[u8], input: &[u8], tag: &[u8],
                                 expected: &[u8]) -> Result<(), DecryptError> {
        let mut output = Vec::with_capacity(input.len());
        let result = decrypt(key, nonce, aad, input, tag, &mut output);

        assert_eq!(&output[..], expected);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_encrypt() {
        selftest::selftest_encrypt();
    }

    #[test]
    fn selftest_decrypt() {
        selftest::selftest_decrypt();
    }

    #[test]
    fn test_encrypt() {
        let mut output = Vec::with_capacity(PLAINTEXT.len());
        let tag = encrypt(KEY, NONCE, AAD, PLAINTEXT.as_bytes(),
                          &mut output).expect("test failed");
        assert_eq!(&output[..], CIPHERTEXT);
        assert_eq!(tag, TAG);
    }

    #[test]
    fn test_decrypt() {
        let mut output = Vec::with_capacity(CIPHERTEXT.len());
        decrypt(KEY, NONCE, AAD, CIPHERTEXT, TAG,
                &mut output).expect("test failed");
        assert_eq!(&output[..], PLAINTEXT.as_bytes());
    }

    static KEY: &'static [u8] = &[
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0];

    static CIPHERTEXT: &'static [u8] = &[
        0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4,
        0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
        0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89,
        0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
        0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee,
        0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
        0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00,
        0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
        0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce,
        0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
        0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd,
        0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
        0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61,
        0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
        0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0,
        0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
        0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46,
        0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
        0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e,
        0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
        0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15,
        0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
        0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea,
        0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
        0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99,
        0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
        0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10,
        0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
        0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94,
        0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
        0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf,
        0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
        0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70,
        0x9b];

    static NONCE: &'static [u8] = &[0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    static AAD: &'static [u8] = &[0xf3, 0x33, 0x88, 0x86,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91];

    static TAG: &'static [u8] = &[
        0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22,
        0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38];

    static PLAINTEXT: &'static str = "\
        Internet-Drafts are draft documents valid for a maximum of six m\
        onths and may be updated, replaced, or obsoleted by other docume\
        nts at any time. It is inappropriate to use Internet-Drafts as r\
        eference material or to cite them other than as /\u{201c}work in prog\
        ress./\u{201d}";
}

#[cfg(all(feature = "bench", test))]
mod bench {
    use test::{Bencher, black_box};
    use super::*;

    #[cfg_attr(feature = "clippy", allow(result_unwrap_used))]
    fn bench_encrypt(b: &mut Bencher, aad: &[u8], data: &[u8]) {
        let key = [!0; 32];
        let nonce = [!0; 12];

        let mut buf = Vec::with_capacity(data.len());

        b.bytes = data.len() as u64;
        b.iter(|| {
            buf.clear();
            encrypt(black_box(&key), black_box(&nonce),
                    black_box(aad), black_box(data),
                    black_box(&mut buf)).unwrap()
        })
    }

    #[cfg_attr(feature = "clippy", allow(result_unwrap_used))]
    fn bench_decrypt(b: &mut Bencher, aad: &[u8], data: &[u8]) {
        let key = [!0; 32];
        let nonce = [!0; 12];

        let mut ciphertext = Vec::with_capacity(data.len());
        let tag = encrypt(&key, &nonce, aad, data, &mut ciphertext).unwrap();
        let input = &ciphertext[..];

        let mut buf = Vec::with_capacity(data.len());

        b.bytes = data.len() as u64;
        b.iter(|| {
            buf.clear();
            decrypt(black_box(&key), black_box(&nonce),
                    black_box(aad), black_box(input), black_box(&tag),
                    black_box(&mut buf)).unwrap()
        })
    }

    #[bench]
    fn bench_encrypt_16(b: &mut Bencher) {
        bench_encrypt(b, &[!0; 16], &[!0; 16])
    }

    #[bench]
    fn bench_encrypt_4k(b: &mut Bencher) {
        bench_encrypt(b, &[!0; 16], &[!0; 4096])
    }

    #[bench]
    fn bench_encrypt_64k(b: &mut Bencher) {
        bench_encrypt(b, &[!0; 16], &[!0; 65536])
    }

    #[bench]
    fn bench_decrypt_16(b: &mut Bencher) {
        bench_decrypt(b, &[!0; 16], &[!0; 16])
    }

    #[bench]
    fn bench_decrypt_4k(b: &mut Bencher) {
        bench_decrypt(b, &[!0; 16], &[!0; 4096])
    }

    #[bench]
    fn bench_decrypt_64k(b: &mut Bencher) {
        bench_decrypt(b, &[!0; 16], &[!0; 65536])
    }
}
