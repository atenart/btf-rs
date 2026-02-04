use std::{mem, slice};

/// Represent any type as a Vec of u8. Works best for packed structs.
pub fn as_u8_vec<T: Sized>(input: &T) -> Vec<u8> {
    unsafe { slice::from_raw_parts((input as *const T) as *const u8, mem::size_of::<T>()) }.to_vec()
}
