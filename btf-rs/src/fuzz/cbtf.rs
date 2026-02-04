//! Fuzzing implementation of the cbtf types.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use arbitrary::*;

use crate::cbtf;

/// Provides a BTF header + data where just enough of the BTF header is valid.
#[derive(Debug)]
#[repr(C)]
pub struct btf_random_data {
    header: cbtf::btf_header,
    data: Vec<u8>,
}

impl<'a> Arbitrary<'a> for btf_random_data {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Self {
            header: cbtf::btf_header {
                #[allow(clippy::mixed_case_hex_literals)]
                magic: 0xeB9F,
                version: 1,
                flags: 0,
                hdr_len: u32::arbitrary(u)?,
                type_off: u32::arbitrary(u)?,
                type_len: u32::arbitrary(u)?,
                str_off: u32::arbitrary(u)?,
                str_len: u32::arbitrary(u)?,
                layout_off: u32::arbitrary(u)?,
                layout_len: u32::arbitrary(u)?,
            },
            data: Vec::<u8>::arbitrary(u)?,
        })
    }
}
