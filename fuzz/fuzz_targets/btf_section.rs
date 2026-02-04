// Fuzz BtfSection using poisoned BTF data as the input.
//
// Use `cargo fuzz run btf_section`.
#![no_main]

use std::{
    cmp,
    io::{Cursor, Write},
};

use memmap2::MmapMut;

use btf_rs::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|btf: fuzz::cbtf::btf_random_data| {
    let buf = &fuzz::as_u8_vec(&btf);

    let _ = fuzz::section::BtfSection::from_reader(&mut Cursor::new(buf));

    let mut mmap = MmapMut::map_anon(cmp::min(buf.len(), 64 * 1024 * 1024)).unwrap();
    (&mut mmap[..]).write_all(buf).unwrap();
    let _ = fuzz::section::BtfSection::from_mmap(mmap.make_read_only().unwrap());
});
