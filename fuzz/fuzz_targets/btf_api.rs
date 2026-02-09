// Fuzz the Btf API.
//
// Use `cargo fuzz run btf_api`.
#![no_main]

use std::sync::OnceLock;

use btf_rs::*;
use libfuzzer_sys::fuzz_target;
use regex::Regex;

static BTF_CACHE: OnceLock<Btf> = OnceLock::new();
static BTF_MMAP: OnceLock<Btf> = OnceLock::new();

fuzz_target!(|input: (u32, &str, &str)| {
    let btf = BTF_CACHE.get_or_init(|| {
        let btf = Btf::from_file_with_backend("../btf-rs/tests/assets/btf/vmlinux", Backend::Cache)
            .unwrap();
        Btf::from_split_file("../btf-rs/tests/assets/btf/openvswitch", &btf).unwrap()
    });
    test_btf_api(btf, input.0, input.1, input.2);

    let btf = BTF_MMAP.get_or_init(|| {
        let btf = Btf::from_file_with_backend("../btf-rs/tests/assets/btf/vmlinux", Backend::Mmap)
            .unwrap();
        Btf::from_split_file("../btf-rs/tests/assets/btf/openvswitch", &btf).unwrap()
    });
    test_btf_api(btf, input.0, input.1, input.2);
});

fn test_btf_api(btf: &Btf, id: u32, name: &str, regex: &str) {
    let _ = btf.resolve_ids_by_name(name);
    let _ = btf.resolve_type_by_id(id);
    let _ = btf.resolve_types_by_name(name);

    if let Ok(re) = Regex::new(regex) {
        let _ = btf.resolve_ids_by_regex(&re);
        let _ = btf.resolve_types_by_regex(&re);
    }
}
