use core::hash::Hasher;

use digest::{
    generic_array::{
        typenum::consts::{U4, U8},
        GenericArray,
    },
    Digest,
};

use crate::XxHash as XxHash64;
use crate::thirty_two::XxHash as XxHash32;

impl Digest for XxHash32 {
    type OutputSize = U4;

    fn new() -> Self {
        Self::default()
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.write(data.as_ref());
    }

    fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self
    where
        Self: Sized,
    {
        self.input(data);
        self
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        (self.finish() as u32).to_be_bytes().into()
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let result = self.clone().result();
        self.reset();
        result
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn output_size() -> usize {
        4
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        Self::new().chain(data).result()
    }
}

impl Digest for XxHash64 {
    type OutputSize = U8;

    fn new() -> Self {
        Self::default()
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.write(data.as_ref());
    }

    fn chain<B: AsRef<[u8]>>(mut self, data: B) -> Self
    where
        Self: Sized,
    {
        self.input(data);
        self
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.finish().to_be_bytes().into()
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let result = self.clone().result();
        self.reset();
        result
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn output_size() -> usize {
        8
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        Self::new().chain(data).result()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::prelude::v1::*;

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks_64() {
        let bytes: Vec<_> = (0..32).map(|_| 0).collect();

        let mut byte_by_byte = XxHash64::new();
        for byte in bytes.chunks(1) {
            byte_by_byte.input(byte);
        }

        let mut one_chunk = XxHash64::new();
        one_chunk.input(&bytes);

        assert_eq!(byte_by_byte.result(), one_chunk.result());
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation_64() {
        let mut hasher = XxHash64::new();
        hasher.input(&[]);
        assert_eq!(hasher.result()[..], 0xef46db3751d8e999u64.to_be_bytes());
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation_64() {
        let mut hasher = XxHash64::new();
        hasher.input(&[42]);
        assert_eq!(hasher.result()[..], 0x0a9edecebeb03ae4u64.to_be_bytes());
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation_64() {
        assert_eq!(
            XxHash64::digest(b"Hello, world!\0")[..],
            0x7b06c531ea43e89fu64.to_be_bytes()
        );
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation_64() {
        let bytes: Vec<_> = (0..100).collect();
        assert_eq!(
            XxHash64::digest(&bytes)[..],
            0x6ac1e58032166597u64.to_be_bytes()
        );
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation_64() {
        let mut hasher = XxHash64::with_seed(0xae0543311b702d91);
        hasher.input(&[]);
        assert_eq!(hasher.result()[..], 0x4b6a04fcdf7a4672u64.to_be_bytes());
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation_64() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash64::with_seed(0xae0543311b702d91);
        hasher.input(&bytes);
        assert_eq!(hasher.result()[..], 0x567e355e0682e1f1u64.to_be_bytes());
    }

    #[test]
    fn ingesting_byte_by_byte_is_equivalent_to_large_chunks_32() {
        let bytes: Vec<_> = (0..32).map(|_| 0).collect();

        let mut byte_by_byte = XxHash32::new();
        for byte in bytes.chunks(1) {
            byte_by_byte.input(byte);
        }

        let mut one_chunk = XxHash32::new();
        one_chunk.input(&bytes);

        assert_eq!(byte_by_byte.result(), one_chunk.result());
    }

    #[test]
    fn hash_of_nothing_matches_c_implementation_32() {
        let mut hasher = XxHash32::new();
        hasher.input(&[]);
        assert_eq!(hasher.result()[..], 0x02cc5d05u32.to_be_bytes());
    }

    #[test]
    fn hash_of_single_byte_matches_c_implementation_32() {
        let mut hasher = XxHash32::new();
        hasher.input(&[42]);
        assert_eq!(hasher.result()[..], 0xe0fe705fu32.to_be_bytes());
    }

    #[test]
    fn hash_of_multiple_bytes_matches_c_implementation_32() {
        assert_eq!(
            XxHash32::digest(b"Hello, world!\0")[..],
            0x9e5e7e93u32.to_be_bytes()
        );
    }

    #[test]
    fn hash_of_multiple_chunks_matches_c_implementation_32() {
        let bytes: Vec<_> = (0..100).collect();
        assert_eq!(
            XxHash32::digest(&bytes)[..],
            0x7f89ba44u32.to_be_bytes()
        );
    }

    #[test]
    fn hash_with_different_seed_matches_c_implementation_32() {
        let mut hasher = XxHash32::with_seed(0x42c91977);
        hasher.input(&[]);
        assert_eq!(hasher.result()[..], 0xd6bf8459u32.to_be_bytes());
    }

    #[test]
    fn hash_with_different_seed_and_multiple_chunks_matches_c_implementation_32() {
        let bytes: Vec<_> = (0..100).collect();
        let mut hasher = XxHash32::with_seed(0x42c91977);
        hasher.input(&bytes);
        assert_eq!(hasher.result()[..], 0x6d2f6c17u32.to_be_bytes());
    }
}
