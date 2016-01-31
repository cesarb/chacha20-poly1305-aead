// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of the Rust distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "clippy", allow(shadow_reuse))]

// Workaround for old Rust compilers. To be removed once 1.7.0 is stable.
//
// Code copied from the Rust standard library.

pub trait CompatCloneFromSlice {
    type Item;

    fn compat_clone_from_slice(&mut self, &[Self::Item]) where Self::Item: Clone;
}

impl<T> CompatCloneFromSlice for [T] {
    type Item = T;

    #[inline]
    fn compat_clone_from_slice(&mut self, src: &[T]) where T: Clone {
        assert!(self.len() == src.len(),
                "destination and source slices have different lengths");
        // NOTE: We need to explicitly slice them to the same length
        // for bounds checking to be elided, and the optimizer will
        // generate memcpy for simple cases (for example T = u8).
        let len = self.len();
        let src = &src[..len];
        for i in 0..len {
            self[i].clone_from(&src[i]);
        }
    }
}
