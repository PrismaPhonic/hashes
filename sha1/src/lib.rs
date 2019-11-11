//! An implementation of the [SHA-1][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate sha1;
//! # fn main() {
//! use sha1::{Sha1, Digest};
//!
//! // create a Sha1 object
//! let mut hasher = Sha1::new();
//!
//! // process input message
//! hasher.input(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 20]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-1
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_buffer;
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
#[cfg(feature = "std")]
extern crate std;
#[cfg(not(feature = "asm"))]
extern crate fake_simd as simd;

#[cfg(feature = "asm")]
extern crate sha1_asm;
#[cfg(feature = "asm")]
#[inline(always)]
fn compress(state: &mut [u32; 5], block: &GenericArray<u8, U64>) {
    let block: &[u8; 64] = unsafe { core::mem::transmute(block) };
    sha1_asm::compress(state, block);
}

#[cfg(not(feature = "asm"))]
mod utils;
#[cfg(not(feature = "asm"))]
use utils::compress;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U20, U64};
use block_buffer::BlockBuffer;
use block_buffer::byteorder::{BE, ByteOrder};
use std::os::raw::c_int;
use std::vec::Vec;

mod consts;
use consts::{STATE_LEN, H};

/// Structure representing the state of a SHA-1 computation
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; STATE_LEN],
    len: u64,
    buffer: BlockBuffer<U64>,
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1{ h: H, len: 0u64, buffer: Default::default()}
    }
}

impl BlockInput for Sha1 {
    type BlockSize = U64;
}

impl Input for Sha1 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        // Assumes that `length_bits<<3` will not overflow
        self.len += input.len() as u64;
        let state = &mut self.h;
        self.buffer.input(input, |d| compress(state, d));
    }
}

impl FixedOutput for Sha1 {
    type OutputSize = U20;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        {
            let state = &mut self.h;
            let l = self.len << 3;
            self.buffer.len64_padding::<BE, _>(l, |d| compress(state, d));
        }
        let mut out = GenericArray::default();
        BE::write_u32_into(&self.h,&mut out);
        out
    }
}

impl Reset for Sha1 {
    fn reset(&mut self) {
        self.h = H;
        self.len = 0;
        self.buffer.reset();
    }
}

impl Sha1 {
    pub fn get_result(&mut self) -> GenericArray<u8, U20> {
        {
            let state = &mut self.h;
            let l = self.len << 3;
            self.buffer.len64_padding::<BE, _>(l, |d| compress(state, d));
        }
        let mut out = GenericArray::default();
        BE::write_u32_into(&self.h,&mut out);
        out
    }

    pub fn digest_starts_with(&mut self, prefix: &Vec<u8>, has_odd_length: bool) -> bool {
        // Add padding to finalize last block.
        {
            let state = &mut self.h;
            let l = self.len << 3;
            self.buffer.len64_padding::<BE, _>(l, |d| compress(state, d));
        }

        let byte_len = prefix.len();

        // Check that state starts with prefix
        // TODO: Make this actually use the length;
        let partial_sum = self.partial_sum(byte_len);

        // even length case
        if !has_odd_length {
            return unsafe {
                memcmp(partial_sum.as_ptr(), prefix.as_ptr(), byte_len) == 0
            }
        }

        // odd length case. we memcmp up to max even length byte, and then check only upper nibble of
        // last byte
        if unsafe {
            memcmp(partial_sum.as_ptr(), prefix.as_ptr(), byte_len-1) != 0
        } {
            return false;
        }

        if prefix[byte_len - 1] >> 4 != partial_sum[byte_len - 1] >> 4 {
            return false;
        }

        true
    }

    // Sum only up to a fixed length.  Used for prefix checking.
    fn partial_sum(&mut self, len: usize) -> [u8; 20] {
        let mut digest = [0; 20];
        digest[0] = (self.h[0] >> 24) as u8;
        digest[1] = (self.h[0] >> 16) as u8;
        digest[2] = (self.h[0] >> 8) as u8;
        digest[3] = (self.h[0] >> 0) as u8;
        digest
    }
}

extern {
    /// Calls implementation provided memcmp.
    ///
    /// Interprets the data as u8.
    ///
    /// Returns 0 for equal, < 0 for less than and > 0 for greater
    /// than.
    fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> c_int;
}

impl_opaque_debug!(Sha1);
impl_write!(Sha1);
