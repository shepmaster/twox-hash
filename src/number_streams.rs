use std::marker::PhantomData;
use std::ptr;

// We should use {u32,u64}::BYTES when they are stable;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;

macro_rules! number_stream(
    ($name:ident, $number_type:ty, $bytes_in_type:expr) => (
#[allow(raw_pointer_derive)]
#[derive(Debug,Copy,Clone)]
struct $name<'a> {
    start: *const $number_type,
    end: *const $number_type,
    marker: PhantomData<&'a ()>
}

impl<'a> $name<'a> {
    fn new(bytes: &'a [u8]) -> ($name<'a>, &'a [u8]) {
        let full_chunks = bytes.len() / $bytes_in_type;
        let (mine, theirs) = bytes.split_at(full_chunks * $bytes_in_type);

        let start = mine.as_ptr() as *const $number_type;
        let end = unsafe { start.offset(full_chunks as isize) };

        let me = $name {
            start: start,
            end: end,
            marker: PhantomData,
        };

        (me, theirs)
    }
}

impl<'a> Iterator for $name<'a> {
    type Item = $number_type;

    fn next(&mut self) -> Option<$number_type> {
        if self.start >= self.end { return None }

        let v: $number_type = unsafe { ptr::read(self.start) };

        self.start = unsafe { self.start.offset(1) };
        Some(v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let cnt = self.count();
        (cnt, Some(cnt))
    }

    fn count(self) -> usize() {
        let total_bytes = self.end as usize - self.start as usize;
        total_bytes / $bytes_in_type
    }
}
));

number_stream!(U32FromBytes, u32, U32_BYTES);
number_stream!(U64FromBytes, u64, U64_BYTES);

/// Converts a slice of bytes into an iterator of numbers.
///
/// The data is always treated as little endian. Only complete ranges
/// of bytes are parsed as the number, any left-over bytes are returned.
// FIXME: Probably doesn't work on big endian machines.
pub trait NumberStreams {
    /// Reads u32s from the bytes
    fn u32_stream(&self) -> (U32FromBytes, &[u8]);
    /// Reads u64s from the bytes
    fn u64_stream(&self) -> (U64FromBytes, &[u8]);
}

impl<'a> NumberStreams for [u8] {
    fn u32_stream(&self) -> (U32FromBytes, &[u8]) { U32FromBytes::new(self) }
    fn u64_stream(&self) -> (U64FromBytes, &[u8]) { U64FromBytes::new(self) }
}

#[cfg(test)]
mod test {
    use ::std::slice;
    use super::{U32_BYTES,U64_BYTES};
    use super::NumberStreams;

    fn u32_slice_as_u8(values: &[u32]) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                values.as_ptr() as *const u8,
                values.len() * U32_BYTES,
            )
        }
    }

    #[test]
    fn can_read_u32_from_bytes() {
        let orig_values: &[u32] = &[0,1];
        let as_u8 = u32_slice_as_u8(orig_values);

        let (iter, rest) = as_u8.u32_stream();
        let values: Vec<_> = iter.collect();

        assert_eq!(&values[..], &orig_values[..]);
        assert!(rest.is_empty());
    }

    #[test]
    fn can_read_u32_from_bytes_with_leftovers() {
        let orig_values: &[u32] = &[0,1];
        let mut as_u8: Vec<_> = u32_slice_as_u8(orig_values).into();
        as_u8.push(42);

        let (iter, rest) = as_u8.u32_stream();
        let values: Vec<_> = iter.collect();

        assert_eq!(&values[..], &orig_values[..]);
        assert_eq!(rest, [42]);
    }

    fn u64_slice_as_u8(values: &[u64]) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                values.as_ptr() as *const u8,
                values.len() * U64_BYTES,
            )
        }
    }

    #[test]
    fn can_read_u64_from_bytes() {
        let orig_values: &[u64] = &[0,1];
        let as_u8 = u64_slice_as_u8(orig_values);

        let (iter, rest) = as_u8.u64_stream();
        let values: Vec<_> = iter.collect();

        assert_eq!(&values[..], &orig_values[..]);
        assert!(rest.is_empty());
    }

    #[test]
    fn can_read_u64_from_bytes_with_leftovers() {
        let orig_values: &[u64] = &[0,1];
        let mut as_u8: Vec<_> = u64_slice_as_u8(orig_values).into();
        as_u8.push(42);

        let (iter, rest) = as_u8.u64_stream();
        let values: Vec<_> = iter.collect();

        assert_eq!(&values[..], &orig_values[..]);
        assert_eq!(rest, [42]);
    }
}
