//! Yet Another Tag Length Value (YATLV) format.
//!
//! Tag-length-value formats are a common way to exchange structured data in a compact and
//! well defined way.  They stand midway between schema rich formats (like `JSON`, `YAML` and `XML`)
//! and compact binary formats that contain no schema information (like `bincode`).
//!
//! One advantage of tag-length-value formats is they support better forwards compatibility
//! than their schema less cousins because they contain just enough information for a parser to
//! skip fields they do not recognise.
//!
//! Unlike many tag-length-value formats no attempt is made to use variable length
//! encodings to reduce the amount of space taken by the 'length'.  This does lead to larger
//! encodings but simplifies the job of the parser and builder significantly.
//!
//! Structure of the format:
//! ```abnf
//! packet       = frame-size frame
//! frame-size   = unsigned32
//! frame        = field-count *field
//! field-count  = unsigned32
//! field        = field-tag field-length field-value
//! field-tag    = unsigned16
//! field-length = unsigned32
//! field-value  = octet-array
//! unsigned16   = %x0000-xFFFF
//! unsigned32   = %x00000000-xFFFFFFFF
//! octet-array  = *%x00-xFF
//! ```
//! Where:
//!
//! * the number `field`s must match `field-count`
//! * the length of `field-value` must match `field-length`.
//! * `unsigned-16` and `unsigned-32` are encoded using big-endian.
//!
//! The root frame can either be encoded as a `frame` or as a `packet`.  Encoding
//! as a `packet` is useful when sending `frame`s across a stream.

const SIZE_BYTES: usize = 4;

/// FrameBuilder can be used to push a frame into a mutable Vec<u8>
/// ```
/// use yatlv::FrameBuilder;
/// let mut data = Vec::with_capacity(100);
/// {
///     FrameBuilder::new(&mut data);
/// }
/// // first 4 bytes indicate the frame has zero fields.
/// assert_eq!(&[0, 0, 0, 0], &data[..]);
/// ```
pub struct FrameBuilder<'a> {
    field_count: u32,
    field_start: usize,
    data: &'a mut Vec<u8>,
}

impl<'a> Drop for FrameBuilder<'a> {
    fn drop(&mut self) {
        self.data[self.field_start..self.field_start + SIZE_BYTES]
            .copy_from_slice(&self.field_count.to_be_bytes())
    }
}

impl<'a> FrameBuilder<'a> {
    pub fn new(data: &mut Vec<u8>) -> FrameBuilder {
        let field_start = data.len();
        data.extend_from_slice(&[0, 0, 0, 0]);

        FrameBuilder {
            field_count: 0,
            field_start,
            data,
        }
    }
}

/// PacketBuilder can be used to push a packet into a mutable Vec<u8>
///
/// ```
/// use yatlv::PacketBuilder;
/// let mut data = Vec::with_capacity(100);
/// {
///     PacketBuilder::new(&mut data);
/// }
/// // first 4 bytes indicate the frame is 4 bytes long
/// // second 4 bytes indicate that the frame has zero fields.
/// assert_eq!(&[0, 0, 0, 4, 0, 0, 0, 0], &data[..]);
/// ```
pub struct PacketBuilder<'a> {
    field_count: u32,
    packet_start: usize,
    data: &'a mut Vec<u8>,
}

impl<'a> Drop for PacketBuilder<'a> {
    fn drop(&mut self) {
        let packet_length = (self.data.len() - self.packet_start - SIZE_BYTES) as u32;
        self.data[self.packet_start..self.packet_start + SIZE_BYTES]
            .copy_from_slice(&packet_length.to_be_bytes());
        self.data[self.packet_start + SIZE_BYTES..self.packet_start + SIZE_BYTES + SIZE_BYTES]
            .copy_from_slice(&self.field_count.to_be_bytes())
    }
}

impl<'a> PacketBuilder<'a> {
    pub fn new(data: &mut Vec<u8>) -> PacketBuilder {
        let packet_start = data.len();
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        PacketBuilder {
            field_count: 0,
            packet_start,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_make_an_empty_frame() {
        let mut data = Vec::with_capacity(100);
        {
            FrameBuilder::new(&mut data);
        }
        assert_eq!(&[0, 0, 0, 0], &data[..]);
    }

    #[test]
    fn can_make_an_empty_packet() {
        let mut data = Vec::with_capacity(100);
        {
            PacketBuilder::new(&mut data);
        }
        assert_eq!(&[0, 0, 0, 4, 0, 0, 0, 0], &data[..]);
    }
}
