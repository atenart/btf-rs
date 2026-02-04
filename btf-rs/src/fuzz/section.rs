//! Fuzzing implementation of the section types.

#![allow(dead_code)]

use std::io::{BufRead, Seek};

use memmap2::Mmap;

use crate::*;

/// Provides a publicly accessible BtfSection.
pub struct BtfSection(section::BtfSection);

impl BtfSection {
    pub fn from_reader<R: Seek + BufRead>(reader: &mut R) -> Result<Self> {
        Ok(Self(section::BtfSection::from_reader(reader, None)?))
    }

    pub fn from_mmap(mmap: Mmap) -> Result<Self> {
        Ok(Self(section::BtfSection::from_mmap(mmap, None)?))
    }
}
