use std::marker::PhantomData;
use std::{ptr,u64};

const U64_BYTES: usize = u64::BYTES;

/// Converts a slice of bytes into an iterator of u64. The data is
/// always treated as little endian!
// FIXME: Probably doesn't work on big endian machines.
struct U64FromBytes<'a> {
    start: *const u64,
    end: *const u64,
    marker: PhantomData<&'a ()>
}

impl<'a> U64FromBytes<'a> {
    /// Returns the iterator and any left-over bytes.
    fn new(bytes: &'a [u8]) -> (U64FromBytes<'a>, &'a [u8]) {
        let full_chunks = bytes.len() / U64_BYTES;
        let (mine, theirs) = bytes.split_at(full_chunks * U64_BYTES);

        let start = mine.as_ptr() as *const u64;
        let end = unsafe { start.offset(full_chunks as isize) };

        let me = U64FromBytes {
            start: start,
            end: end,
            marker: PhantomData,
        };

        (me, theirs)
    }
}

impl<'a> Iterator for U64FromBytes<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.start >= self.end { return None }

        let v: u64 = unsafe { ptr::read(self.start) };

        self.start = unsafe { self.start.offset(1) };
        Some(v)
    }
}

pub trait NumberStreams {
    fn u64_stream(&self) -> (U64FromBytes, &[u8]);
}

impl<'a> NumberStreams for [u8] {
    fn u64_stream(&self) -> (U64FromBytes, &[u8]) { U64FromBytes::new(self) }
}

#[cfg(test)]
mod test {
    use ::std::slice;
    use super::{U64FromBytes,U64_BYTES};

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

        let (iter, rest) = U64FromBytes::new(as_u8);
        let values: Vec<_> = iter.collect();

        assert_eq!(&values[..], &orig_values[..]);
        assert!(rest.is_empty());
    }

    #[test]
    fn can_read_u64_from_bytes_with_leftovers() {
        let orig_values: &[u64] = &[0,1];
        let mut as_u8: Vec<_> = u64_slice_as_u8(orig_values).into();
        as_u8.push(42);

        let (iter, rest) = U64FromBytes::new(&as_u8);
        let values: Vec<_> = iter.collect();

        assert_eq!(&values[..], &orig_values[..]);
        assert_eq!(rest, [42]);
    }
}
