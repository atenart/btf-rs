//! Fuzzing implementation of the btf types.

#![allow(dead_code)]

use std::ops::Deref;

use crate::*;

/// Provides a publicly accessible Type.
pub struct Type(btf::Type);

impl Deref for Type {
    type Target = btf::Type;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Type {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let bt = cbtf::btf_type::from_bytes(data, &cbtf::Endianness::Little)?;
        Ok(Self(btf::Type::from_bytes(
            &data[3..],
            &cbtf::Endianness::Little,
            bt,
        )?))
    }
}
