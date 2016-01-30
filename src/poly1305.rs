// Copyright 2016 chacha20-poly1305-aead Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// The 130-bit accumulator is split into five 26-bit limbs, with the
// carry between the limbs delayed.
//
// The reduction steps use the following identity:
//
// a×2^n ≡ a×c (mod 2^n−c)
//
// For Poly1305, the identity becomes:
//
// a×2^130 ≡ a×5 (mod 2^130−5)
//
// That is, any limb or carry above 2^130 is multiplied by 5 and added
// back to the lower limbs.
//
// Based on the algorithm from https://github.com/floodyberry/poly1305-donna

#[derive(Clone, Debug)]
pub struct Poly1305 {
    /// Accumulator: 5x26-bit
    a: [u32; 5],
    /// Multiplier: 5x26-bit
    r: [u32; 5],
    /// Secret key: 4x32-bit
    s: [u32; 4],
}

impl Poly1305 {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == 32);

        Poly1305 {
            a: [0; 5],

            // r &= 0x0ffffffc_0ffffffc_0ffffffc_0fffffff;
            r: [u32_from_le(&key[ 0.. 4])      & 0x03ffffff,
                u32_from_le(&key[ 3.. 7]) >> 2 & 0x03ffff03,
                u32_from_le(&key[ 6..10]) >> 4 & 0x03ffc0ff,
                u32_from_le(&key[ 9..13]) >> 6 & 0x03f03fff,
                u32_from_le(&key[12..16]) >> 8 & 0x000fffff],

            s: [u32_from_le(&key[16..20]),
                u32_from_le(&key[20..24]),
                u32_from_le(&key[24..28]),
                u32_from_le(&key[28..32])],
        }
    }

    pub fn block(&mut self, msg: &[u8]) {
        assert!(msg.len() == 16);
        self.accumulate(u32_from_le(&msg[ 0.. 4])      & 0x03ffffff,
                        u32_from_le(&msg[ 3.. 7]) >> 2 & 0x03ffffff,
                        u32_from_le(&msg[ 6..10]) >> 4 & 0x03ffffff,
                        u32_from_le(&msg[ 9..13]) >> 6 & 0x03ffffff,
                        u32_from_le(&msg[12..16]) >> 8 | (1 <<  24));
    }

    pub fn last_block(mut self, msg: &[u8]) -> [u32; 4] {
        if !msg.is_empty() {
            assert!(msg.len() <= 16);

            let mut buf = [0; 17];
            buf[..msg.len()].clone_from_slice(msg);
            buf[msg.len()] = 1;

            self.accumulate(u32_from_le(&buf[ 0.. 4])      & 0x03ffffff,
                            u32_from_le(&buf[ 3.. 7]) >> 2 & 0x03ffffff,
                            u32_from_le(&buf[ 6..10]) >> 4 & 0x03ffffff,
                            u32_from_le(&buf[ 9..13]) >> 6 & 0x03ffffff,
                            u32_from_le(&buf[13..17]));
        }

        self.tag()
    }

    fn padded_block(&mut self, msg: &[u8]) {
        assert!(msg.len() <= 16);
        let mut buf = [0; 16];
        buf[..msg.len()].clone_from_slice(msg);
        self.block(&buf);
    }

    pub fn padded_blocks(&mut self, mut msg: &[u8]) {
        while msg.len() >= 16 {
            self.block(&msg[..16]);
            msg = &msg[16..];
        }
        if !msg.is_empty() {
            self.padded_block(msg);
        }
    }

    fn accumulate(&mut self, n0: u32, n1: u32, n2: u32, n3: u32, n4: u32) {
        self.a[0] += n0;
        self.a[1] += n1;
        self.a[2] += n2;
        self.a[3] += n3;
        self.a[4] += n4;
        self.mul_r_mod_p();
    }

    #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
    fn mul_r_mod_p(&mut self) {
        // t = r * a; high limbs multiplied by 5 and added to low limbs
        let mut t = [0; 5];

        t[0] +=      self.r[0]  as u64 * self.a[0] as u64;
        t[1] +=      self.r[0]  as u64 * self.a[1] as u64;
        t[2] +=      self.r[0]  as u64 * self.a[2] as u64;
        t[3] +=      self.r[0]  as u64 * self.a[3] as u64;
        t[4] +=      self.r[0]  as u64 * self.a[4] as u64;

        t[0] += (5 * self.r[1]) as u64 * self.a[4] as u64;
        t[1] +=      self.r[1]  as u64 * self.a[0] as u64;
        t[2] +=      self.r[1]  as u64 * self.a[1] as u64;
        t[3] +=      self.r[1]  as u64 * self.a[2] as u64;
        t[4] +=      self.r[1]  as u64 * self.a[3] as u64;

        t[0] += (5 * self.r[2]) as u64 * self.a[3] as u64;
        t[1] += (5 * self.r[2]) as u64 * self.a[4] as u64;
        t[2] +=      self.r[2]  as u64 * self.a[0] as u64;
        t[3] +=      self.r[2]  as u64 * self.a[1] as u64;
        t[4] +=      self.r[2]  as u64 * self.a[2] as u64;

        t[0] += (5 * self.r[3]) as u64 * self.a[2] as u64;
        t[1] += (5 * self.r[3]) as u64 * self.a[3] as u64;
        t[2] += (5 * self.r[3]) as u64 * self.a[4] as u64;
        t[3] +=      self.r[3]  as u64 * self.a[0] as u64;
        t[4] +=      self.r[3]  as u64 * self.a[1] as u64;

        t[0] += (5 * self.r[4]) as u64 * self.a[1] as u64;
        t[1] += (5 * self.r[4]) as u64 * self.a[2] as u64;
        t[2] += (5 * self.r[4]) as u64 * self.a[3] as u64;
        t[3] += (5 * self.r[4]) as u64 * self.a[4] as u64;
        t[4] +=      self.r[4]  as u64 * self.a[0] as u64;

        // propagate carries
        t[1] += t[0] >> 26;
        t[2] += t[1] >> 26;
        t[3] += t[2] >> 26;
        t[4] += t[3] >> 26;

        // mask out carries
        self.a[0] = t[0] as u32 & 0x03ffffff;
        self.a[1] = t[1] as u32 & 0x03ffffff;
        self.a[2] = t[2] as u32 & 0x03ffffff;
        self.a[3] = t[3] as u32 & 0x03ffffff;
        self.a[4] = t[4] as u32 & 0x03ffffff;

        // propagate high limb carry
        self.a[0] += (t[4] >> 26) as u32 * 5;
        self.a[1] += self.a[0] >> 26;

        // mask out carries
        self.a[0] &= 0x03ffffff;

        // A carry of at most 1 bit has been left in self.a[1]
    }

    fn propagate_carries(&mut self) {
        // propagate carries
        self.a[2] +=  self.a[1] >> 26;
        self.a[3] +=  self.a[2] >> 26;
        self.a[4] +=  self.a[3] >> 26;
        self.a[0] += (self.a[4] >> 26) * 5;
        self.a[1] +=  self.a[0] >> 26;

        // mask out carries
        self.a[0] &= 0x03ffffff;
        self.a[1] &= 0x03ffffff;
        self.a[2] &= 0x03ffffff;
        self.a[3] &= 0x03ffffff;
        self.a[4] &= 0x03ffffff;
    }

    fn reduce_mod_p(&mut self) {
        self.propagate_carries();

        let mut t = self.a;

        // t = a - p
        t[0] += 5;
        t[4]  = t[4].wrapping_sub(1 << 26);

        // propagate carries
        t[1] +=                   t[0] >> 26;
        t[2] +=                   t[1] >> 26;
        t[3] +=                   t[2] >> 26;
        t[4]  = t[4].wrapping_add(t[3] >> 26);

        // mask out carries
        t[0] &= 0x03ffffff;
        t[1] &= 0x03ffffff;
        t[2] &= 0x03ffffff;
        t[3] &= 0x03ffffff;

        // constant-time select between (a - p) if non-negative, (a) otherwise
        let mask = (t[4] >> 31).wrapping_sub(1);
        self.a[0] = t[0] & mask | self.a[0] & !mask;
        self.a[1] = t[1] & mask | self.a[1] & !mask;
        self.a[2] = t[2] & mask | self.a[2] & !mask;
        self.a[3] = t[3] & mask | self.a[3] & !mask;
        self.a[4] = t[4] & mask | self.a[4] & !mask;
    }

    #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
    pub fn tag(mut self) -> [u32; 4] {
        self.reduce_mod_p();

        // convert from 5x26-bit to 4x32-bit
        let a = [self.a[0]       | self.a[1] << 26,
                 self.a[1] >>  6 | self.a[2] << 20,
                 self.a[2] >> 12 | self.a[3] << 14,
                 self.a[3] >> 18 | self.a[4] <<  8];

        // t = a + s
        let mut t = [a[0] as u64 + self.s[0] as u64,
                     a[1] as u64 + self.s[1] as u64,
                     a[2] as u64 + self.s[2] as u64,
                     a[3] as u64 + self.s[3] as u64];

        // propagate carries
        t[1] += t[0] >> 32;
        t[2] += t[1] >> 32;
        t[3] += t[2] >> 32;

        // mask out carries
        [(t[0] as u32).to_le(),
         (t[1] as u32).to_le(),
         (t[2] as u32).to_le(),
         (t[3] as u32).to_le()]
    }
}

#[inline]
fn u32_from_le(src: &[u8]) -> u32 {
    use std::mem::size_of;
    use std::ptr::copy_nonoverlapping;

    assert!(src.len() == size_of::<u32>());
    unsafe {
        let mut value = 0;
        copy_nonoverlapping(src.as_ptr(),
                            &mut value as *mut u32 as *mut u8,
                            size_of::<u32>());
        u32::from_le(value)
    }
}

/// Runs the self-test for the poly1305 authenticator.
#[cold]
pub fn selftest() {
    let key = [0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
               0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
               0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
               0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b];
    let msg = b"Cryptographic Forum Research Group";
    let tag = [0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
               0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9];

    selftest_noinline(&key, msg, &tag);
}

#[inline(never)]
#[cold]
fn selftest_noinline(key: &[u8], msg: &[u8], expected: &[u8]) {
    use as_bytes::AsBytes;

    let mut state = Poly1305::new(key);
    state.block(&msg[ 0..16]);
    state.block(&msg[16..32]);
    let tag = state.last_block(&msg[32..]);

    assert_eq!(tag.as_bytes(), expected);
}

#[cfg(test)]
mod tests {
    use as_bytes::AsBytes;
    use super::Poly1305;

    #[test]
    fn selftest() {
        super::selftest();
    }

    #[test]
    fn test_vector_1() {
        let mut state = Poly1305::new(&[0; 32]);
        state.block(&[0; 16]);
        state.block(&[0; 16]);
        state.block(&[0; 16]);
        state.block(&[0; 16]);
        assert_eq!(state.tag().as_bytes(), &[0; 16]);
    }

    static TEXT: &'static [u8] = b"\
        Any submission to the IETF intended by the Contributor for publi\
        cation as all or part of an IETF Internet-Draft or RFC and any s\
        tatement made within the context of an IETF activity is consider\
        ed an \"IETF Contribution\". Such statements include oral statemen\
        ts in IETF sessions, as well as written and electronic communica\
        tions made at any time or place, which are addressed to";

    #[test]
    fn test_vector_2() {
        let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
                   0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e];
        let mut msg = TEXT;

        let mut state = Poly1305::new(&key);
        while msg.len() >= 16 {
            state.block(&msg[..16]);
            msg = &msg[16..];
        }
        let tag = state.last_block(msg);

        assert_eq!(tag.as_bytes(),
                   &[0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
                     0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e]);
    }

    #[test]
    fn test_vector_3() {
        let key = [0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
                   0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut msg = TEXT;

        let mut state = Poly1305::new(&key);
        while msg.len() >= 16 {
            state.block(&msg[..16]);
            msg = &msg[16..];
        }
        let tag = state.last_block(msg);

        assert_eq!(tag.as_bytes(),
                   &[0xf3, 0x47, 0x7e, 0x7c, 0xd9, 0x54, 0x17, 0xaf,
                     0x89, 0xa6, 0xb8, 0x79, 0x4c, 0x31, 0x0c, 0xf0]);
    }

    #[test]
    fn test_vector_4() {
        let key = [0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
                   0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
                   0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
                   0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0];
        let mut msg: &[u8] = b"\
            'Twas brillig, and the slithy toves\nDid gyre and gimble in the w\
            abe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";

        let mut state = Poly1305::new(&key);
        while msg.len() >= 16 {
            state.block(&msg[..16]);
            msg = &msg[16..];
        }
        let tag = state.last_block(msg);

        assert_eq!(tag.as_bytes(),
                   &[0x45, 0x41, 0x66, 0x9a, 0x7e, 0xaa, 0xee, 0x61,
                     0xe7, 0x08, 0xdc, 0x7c, 0xbc, 0xc5, 0xeb, 0x62]);
    }

    #[test]
    fn test_vector_5() {
        let key = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut state = Poly1305::new(&key);
        state.block(&[0xff; 16]);

        assert_eq!(state.tag().as_bytes(),
                   &[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_vector_6() {
        let key = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        let mut state = Poly1305::new(&key);
        state.block(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(state.tag().as_bytes(),
                   &[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_vector_7() {
        let key = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut state = Poly1305::new(&key);
        state.block(&[0xff; 16]);
        state.block(&[0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        state.block(&[0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(state.tag().as_bytes(),
                   &[0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_vector_8() {
        let key = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut state = Poly1305::new(&key);
        state.block(&[0xff; 16]);
        state.block(&[0xfb, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
                      0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe]);
        state.block(&[0x01; 16]);

        assert_eq!(state.tag().as_bytes(), &[0; 16]);
    }

    #[test]
    fn test_vector_9() {
        let key = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut state = Poly1305::new(&key);
        state.block(&[0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

        assert_eq!(state.tag().as_bytes(),
                   &[0xfa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_vector_10() {
        let key = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut state = Poly1305::new(&key);
        state.block(&[0xe3, 0x35, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0xb9,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        state.block(&[0x33, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0x79, 0xcd,
                      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        state.block(&[0; 16]);
        state.block(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(state.tag().as_bytes(),
                   &[0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_vector_11() {
        let key = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let mut state = Poly1305::new(&key);
        state.block(&[0xe3, 0x35, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0xb9,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        state.block(&[0x33, 0x94, 0xd7, 0x50, 0x5e, 0x43, 0x79, 0xcd,
                      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        state.block(&[0; 16]);

        assert_eq!(state.tag().as_bytes(),
                   &[0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}

#[cfg(all(feature = "bench", test))]
mod bench {
    use test::{Bencher, black_box};
    use super::Poly1305;

    #[bench]
    fn bench_new(b: &mut Bencher) {
        let key = [!0; 32];

        b.bytes = 32;
        b.iter(|| {
            Poly1305::new(black_box(&key))
        })
    }

    #[bench]
    fn bench_block(b: &mut Bencher) {
        let mut state = Poly1305::new(&[!0; 32]);
        let msg = [!0; 16];

        b.bytes = 16;
        b.iter(|| {
            black_box(&mut state).block(black_box(&msg))
        })
    }

    #[bench]
    fn bench_last_block(b: &mut Bencher) {
        let state = Poly1305::new(&[!0; 32]);
        let msg = [!0; 16];

        b.bytes = 16;
        b.iter(|| {
            black_box(&state).clone().last_block(black_box(&msg))
        })
    }

    #[bench]
    fn bench_tag(b: &mut Bencher) {
        let state = Poly1305::new(&[!0; 32]);

        b.bytes = 16;
        b.iter(|| {
            black_box(&state).clone().tag()
        })
    }
}
