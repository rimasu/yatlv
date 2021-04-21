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
//! packet-frame = frame-size frame
//! frame-size   = unsigned32
//! frame        = field-count *field
//! field-count  = unsigned32
//! field        = field-tag field-length field-value
//! field-tag    = unsigned16
//! field-length = unsigned32
//! field-value  = octet-array
//! unsigned16   = 0x0000-0xFFFF
//! unsigned32   = 0x00000000-0xFFFFFFFF
//! octet-array  = *0x00-0xFF
//! ```
//! Where:
//!
//! * the number `field`s must match `field-count`
//! * the length of `field-value` must match `field-length`.
//! * `unsigned-16` and `unsigned-32` are encoded using big-endian.
//!
//! The root frame can either be encoded as a `frame` or as a `packet-frame`.  Encoding
//! as a `packet-frame` is useful when sending `frame`s across a stream.
//!
//! Although applications can store arbitrary data in `field-value` the follow
//! conventions should normally be observed:
//!
//! * numbers use big-endian encoding
//! * boolean values are encoded using a single byte (`0x00`=`false`, `0xFF`=`true`)
//! * text is encoded as UTF-8
//!

use std::convert::TryInto;

const SIZE_BYTES: usize = 4;

/// FrameBuilderLike defines the methods common to [FrameBuilder] and [PacketFrameBuilder].
pub trait FrameBuilderLike {
    /// Add a slice of data as a field to the frame.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let data = &[90, 9];
    ///     bld.add_data(tag, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 2, // field-length
    ///     90, 9 // field-value
    /// ], &data[..]);
    /// ```
    fn add_data(&mut self, tag: u16, value: &[u8]);

    /// Create a new child frame builder.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let mut child_bld = bld.add_child(45);
    ///     let tag2 = 60;
    ///     let data = &[90, 9];
    ///     child_bld.add_data(60, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 12, // field-length
    ///     0, 0, 0, 1, // child field count
    ///     0, 60, // child field-tag2
    ///     0, 0, 0, 2, // child field-length
    ///     90, 9 // child field-value
    /// ], &data[..]);
    /// ```
    fn add_child(&mut self, tag: u16) -> PacketFrameBuilder;

    /// Add a bool flied to the frame.
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     bld.add_bool(1022, true);
    ///     bld.add_bool(1021, false);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 2, // field count = 1
    ///     3, 254, // tag = 1022
    ///     0, 0, 0, 1,  // field length = 2
    ///     255,  // field value
    ///     3, 253, // tag = 1021
    ///     0, 0, 0, 1,  // field length = 2
    ///     0  // field value
    /// ], &data[..]);
    /// ```
    fn add_bool(&mut self, tag: u16, value: bool) {
        self.add_u8(tag, if value { 0xFF } else { 0x00 })
    }

    /// Add a u8 field to the frame.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let data = 7;
    ///     bld.add_u8(tag, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 1, // field-length
    ///     7 // field-value
    /// ], &data[..]);
    /// ```
    fn add_u8(&mut self, tag: u16, value: u8) {
        self.add_data(tag, &value.to_be_bytes())
    }

    /// Add a u16 field to the frame.
    ///
    /// This method will always use a two byte encoding
    /// for the value.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let data = 7;
    ///     bld.add_u16(tag, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 2, // field-length
    ///     0, 7 // field-value
    /// ], &data[..]);
    /// ```
    fn add_u16(&mut self, tag: u16, value: u16) {
        self.add_data(tag, &value.to_be_bytes())
    }

    /// Add a compact u16 field to the frame.
    ///
    /// If the value can fit into a `u8` then value
    /// is encoded as if `add_u8` was called.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     bld.add_compact_u16(1, 0x100);
    ///     bld.add_compact_u16(2, 0xFF);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 2, // field count
    ///     0, 1, // field-tag
    ///     0, 0, 0, 2, // field-length
    ///     1, 0, // field-value,
    ///     0, 2, // field-tag
    ///     0, 0, 0, 1, // field-length
    ///     255 // field-value
    /// ], &data[..]);
    /// ```
    fn add_compact_u16(&mut self, tag: u16, value: u16) {
        if value <= 0xFF {
            self.add_u8(tag, value as u8)
        } else {
            self.add_u16(tag, value)
        }
    }

    /// Add a u32 field to the frame.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let data = 7;
    ///     bld.add_u32(tag, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 4, // field-length
    ///     0, 0, 0, 7 // field-value
    /// ], &data[..]);
    /// ```
    fn add_u32(&mut self, tag: u16, value: u32) {
        self.add_data(tag, &value.to_be_bytes())
    }

    /// Add a u32 field to the frame.
    ///
    /// If the value can fit into a `u16` then value
    /// is encoded as if `add_compact_u16` was called.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     bld.add_compact_u32(1, 0x10000);
    ///     bld.add_compact_u32(2, 0xFFFF);
    ///     bld.add_compact_u32(3, 0xFF);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 3, // field count
    ///     0, 1,       // field-tag 1
    ///     0, 0, 0, 4, // field-length
    ///     0, 1, 0, 0, // field-value,
    ///     0, 2,       // field-tag 2
    ///     0, 0, 0, 2, // field-length
    ///     255, 255,   // field-value
    ///     0, 3,       // field-tag 3
    ///     0, 0, 0, 1, // field-length
    ///     255         // field-value
    /// ], &data[..]);
    /// ```
    fn add_compact_u32(&mut self, tag: u16, value: u32) {
        if value <= 0xFFFF {
            self.add_compact_u16(tag, value as u16)
        } else {
            self.add_u32(tag, value)
        }
    }

    /// Add a u64 field to the frame.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let data = 7;
    ///     bld.add_u64(tag, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 8, // field-length
    ///     0, 0, 0, 0, 0, 0, 0, 7 // field-value
    /// ], &data[..]);
    /// ```
    fn add_u64(&mut self, tag: u16, value: u64) {
        self.add_data(tag, &value.to_be_bytes())
    }

    /// Add a u64 field to the frame.
    ///
    /// If the value can fit into a `u32` then value
    /// is encoded as if `add_compact_u32` was called.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     bld.add_compact_u64(1, 0x100000000);
    ///     bld.add_compact_u64(2, 0xFFFFFFFF);
    ///     bld.add_compact_u64(3, 0xFFFF);
    ///     bld.add_compact_u64(4, 0xFF);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 4,             // field count
    ///     0, 1,                   // field-tag 1
    ///     0, 0, 0, 8,             // field-length
    ///     0, 0, 0, 1, 0, 0, 0, 0, // field-value,
    ///     0, 2,                   // field-tag 2
    ///     0, 0, 0, 4,             // field-length
    ///     255, 255, 255, 255,     // field-value
    ///     0, 3,                   // field-tag 3
    ///     0, 0, 0, 2,             // field-length
    ///     255, 255,               // field-value
    ///     0, 4,                   // field-tag 4
    ///     0, 0, 0, 1,             // field-length
    ///     255                     // field-value
    /// ], &data[..]);
    /// ```
    fn add_compact_u64(&mut self, tag: u16, value: u64) {
        if value <= 0xFFFFFFFF {
            self.add_compact_u32(tag, value as u32)
        } else {
            self.add_u64(tag, value)
        }
    }

    /// Add a UTF-8 field to the frame.
    ///
    /// ```
    /// use yatlv::{FrameBuilder, FrameBuilderLike};
    /// let mut data = Vec::with_capacity(100);
    /// {
    ///     let mut bld = FrameBuilder::new(&mut data);
    ///     let tag = 45;
    ///     let data = "hello";
    ///     bld.add_utf8(tag, data);
    /// }
    /// assert_eq!(&[
    ///     0, 0, 0, 1, // field count
    ///     0, 45,// field-tag
    ///     0, 0, 0, 5, // field-length
    ///     104, 101, 108, 108, 111 // field-value
    /// ], &data[..]);
    /// ```
    fn add_utf8<S>(&mut self, tag: u16, value: S)
        where
            S: AsRef<str>,
    {
        self.add_data(tag, &value.as_ref().as_bytes())
    }
}

/// FrameBuilder can be used to push a frame into a mutable `Vec<u8>`
///
/// For usage details see [FrameBuilderLike].
///
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

impl<'a> FrameBuilderLike for FrameBuilder<'a> {
    fn add_data(&mut self, tag: u16, value: &[u8]) {
        self.field_count += 1;
        self.data.reserve(6 + value.len());
        self.data.extend_from_slice(&tag.to_be_bytes());
        self.data
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.data.extend_from_slice(value);
    }

    fn add_child(&mut self, tag: u16) -> PacketFrameBuilder {
        self.field_count += 1;
        self.data.reserve(6);
        self.data.extend_from_slice(&tag.to_be_bytes());
        PacketFrameBuilder::new(self.data)
    }
}

/// PacketBuilder can be used to push a packet-frame into a mutable `Vec<u8>`
///
/// For usage details see [FrameBuilderLike].
/// ```
/// use yatlv::PacketFrameBuilder;
/// let mut data = Vec::with_capacity(100);
/// {
///     PacketFrameBuilder::new(&mut data);
/// }
/// // first 4 bytes indicate the frame is 4 bytes long
/// // second 4 bytes indicate that the frame has zero fields.
/// assert_eq!(&[0, 0, 0, 4, 0, 0, 0, 0], &data[..]);
/// ```
pub struct PacketFrameBuilder<'a> {
    field_count: u32,
    packet_start: usize,
    data: &'a mut Vec<u8>,
}

impl<'a> Drop for PacketFrameBuilder<'a> {
    fn drop(&mut self) {
        let packet_length = (self.data.len() - self.packet_start - SIZE_BYTES) as u32;
        self.data[self.packet_start..self.packet_start + SIZE_BYTES]
            .copy_from_slice(&packet_length.to_be_bytes());
        self.data[self.packet_start + SIZE_BYTES..self.packet_start + SIZE_BYTES + SIZE_BYTES]
            .copy_from_slice(&self.field_count.to_be_bytes())
    }
}

impl<'a> PacketFrameBuilder<'a> {
    pub fn new(data: &mut Vec<u8>) -> PacketFrameBuilder {
        let packet_start = data.len();
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        PacketFrameBuilder {
            field_count: 0,
            packet_start,
            data,
        }
    }
}

impl<'a> FrameBuilderLike for PacketFrameBuilder<'a> {
    fn add_data(&mut self, tag: u16, value: &[u8]) {
        self.field_count += 1;
        self.data.reserve(6 + value.len());
        self.data.extend_from_slice(&tag.to_be_bytes());
        self.data
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.data.extend_from_slice(value);
    }

    fn add_child(&mut self, tag: u16) -> PacketFrameBuilder {
        self.field_count += 1;
        self.data.reserve(6);
        self.data.extend_from_slice(&tag.to_be_bytes());
        PacketFrameBuilder::new(self.data)
    }
}

/// Library Error Type
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The frame must start with four bytes that indicate the number fields
    /// in the frame (encoded as big-endian u32)
    IncompleteFrameFieldCount,

    /// Each field must start with a two byte tag (big-endian u16) and a
    /// four byte length (big-endian u32).
    IncompleteFieldTagOrLength,

    /// Each field must have a value that is field-length long
    /// This error as expected and actual lengths.
    IncompleteFieldValue(usize, usize),
}

/// Library Result Type
pub type Result<T> = std::result::Result<T, Error>;

struct FrameParserField<'a> {
    tag: u16,
    value: &'a [u8],
}

/// FrameParser can be used to access field encoded as a frame.
pub struct FrameParser<'a> {
    fields: Vec<FrameParserField<'a>>
}

fn read_frame_field_count(data: &[u8]) -> Result<(u32, &[u8])> {
    if data.len() >= 4 {
        let (field_count_bytes, tail) = data.split_at(4);
        let field_count = u32::from_be_bytes(field_count_bytes.try_into().unwrap());
        Ok((field_count, tail))
    } else {
        Err(Error::IncompleteFrameFieldCount)
    }
}

fn read_field_tag_and_length(data: &[u8]) -> Result<(u16, usize, &[u8])> {
    if data.len() >= 6 {
        let (tag_bytes, tail) = data.split_at(2);
        let tag = u16::from_be_bytes(tag_bytes.try_into().unwrap());
        let (length_bytes, tail) = tail.split_at(4);
        let length = u32::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
        Ok((tag, length, tail))
    } else {
        Err(Error::IncompleteFieldTagOrLength)
    }
}

fn read_field_value(data: &[u8], field_length: usize) -> Result<(&[u8], &[u8])> {
    if data.len() >= field_length {
        Ok(data.split_at(field_length))
    } else {
        Err(Error::IncompleteFieldValue(field_length, data.len()))
    }
}

impl<'a> FrameParser<'a> {
    /// ```
    /// # use yatlv::{FrameParser, FrameBuilder, FrameBuilderLike, Result};
    /// # fn main() -> Result<()> {
    /// # let mut frame_data = Vec::new();
    /// # {
    /// #     let mut bld = FrameBuilder::new(&mut frame_data);
    /// #     bld.add_data(12, &[4, 5]);
    /// # }
    /// #
    /// // Assuming frame_data contains a value frame with a single data field (tag=12, value=[4, 5])
    /// let parser = FrameParser::new(&frame_data)?;
    /// let expected: &[u8] = &[4, 5];
    /// assert_eq!(Some(expected), parser.get_data(12));
    /// # Ok(()) }
    ///  ```
    pub fn new(frame_data: &[u8]) -> Result<FrameParser> {
        let (field_count, mut body) = read_frame_field_count(frame_data)?;
        let mut fields = Vec::with_capacity(field_count as usize);
        for _ in 0..field_count {
            let (tag, length, tail) = read_field_tag_and_length(body)?;
            let (value, tail) = read_field_value(tail, length)?;
            fields.push(FrameParserField { tag, value });
            body = tail
        }
        Ok(FrameParser { fields })
    }

    /// Read field from frame.
    /// ```
    /// # use yatlv::{FrameParser, FrameBuilder, FrameBuilderLike, Result};
    /// # fn main() -> Result<()> {
    /// # let mut frame_data = Vec::new();
    /// # {
    /// #     let mut bld = FrameBuilder::new(&mut frame_data);
    /// #     bld.add_data(12, &[4, 5]);
    /// # }
    /// #
    /// // Assuming frame_data contains a value frame with a single data field (tag=12, value=[4, 5])
    /// let parser = FrameParser::new(&frame_data)?;
    /// let expected: &[u8] = &[4, 5];
    /// assert_eq!(Some(expected), parser.get_data(12));
    /// # Ok(()) }
    ///  ```
    pub fn get_data(&self, search_tag: u16) -> Option<&[u8]> {
        for field in &self.fields {
            if field.tag == search_tag {
                return Some(field.value);
            }
        }
        None
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
    fn can_make_an_empty_packet_frame() {
        let mut data = Vec::with_capacity(100);
        {
            PacketFrameBuilder::new(&mut data);
        }
        assert_eq!(&[0, 0, 0, 4, 0, 0, 0, 0], &data[..]);
    }

    #[test]
    fn can_add_data_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_data(1022, &[9, 255]);
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 2, // field length = 2
                9, 255, // field value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_data_to_packet_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = PacketFrameBuilder::new(&mut data);
            bld.add_data(1022, &[9, 255]);
        }
        assert_eq!(
            &[
                0, 0, 0, 12, // frame size = 12
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 2, // field length = 2
                9, 255, // field value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_child_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            let mut child_bld = bld.add_child(1022);
            child_bld.add_data(60, &[9, 255])
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 12, // child frame size
                0, 0, 0, 1, // child frame field count
                0, 60, // field-tag in child frame
                0, 0, 0, 2, // field-length in child frame
                9, 255 // field-value in child frame
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_child_to_packet_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = PacketFrameBuilder::new(&mut data);
            let mut child_bld = bld.add_child(1022);
            child_bld.add_data(60, &[9, 255])
        }
        assert_eq!(
            &[
                0, 0, 0, 22, // packet size
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 12, // child frame size
                0, 0, 0, 1, // child frame field count
                0, 60, // field-tag in child frame
                0, 0, 0, 2, // field-length in child frame
                9, 255 // field-value in child frame
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_bool_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_bool(1022, true);
            bld.add_bool(1021, false);
        }
        assert_eq!(
            &[
                0, 0, 0, 2, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 1,   // field length = 2
                255, // field value
                3, 253, // tag = 1021
                0, 0, 0, 1, // field length = 2
                0  // field value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_u8_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_u8(1022, 89);
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 1,  // field length = 2
                89  // field value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_u16_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_u16(1022, 1009);
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 2, // field length = 2
                3, 241 // field value (1009)
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_compact_u16_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_compact_u16(1, 0x100);
            bld.add_compact_u16(2, 0xFF);
        }
        assert_eq!(
            &[
                0, 0, 0, 2, // field count
                0, 1, // field-tag
                0, 0, 0, 2, // field-length
                1, 0, // field-value,
                0, 2, // field-tag
                0, 0, 0, 1,   // field-length
                255  // field-value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_u32_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_u32(1022, 156090);
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 4, // field length = 2
                0, 2, 97, 186 // field value (156090)
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_compact_u32_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_compact_u32(1, 0x10000);
            bld.add_compact_u32(2, 0xFFFF);
            bld.add_compact_u32(3, 0xFF);
        }
        assert_eq!(
            &[
                0, 0, 0, 3, // field count
                0, 1, // field-tag 1
                0, 0, 0, 4, // field-length
                0, 1, 0, 0, // field-value,
                0, 2, // field-tag 2
                0, 0, 0, 2, // field-length
                255, 255, // field-value
                0, 3, // field-tag 3
                0, 0, 0, 1,   // field-length
                255  // field-value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_u64_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_u64(1022, 156234234090);
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 8, // field length = 2
                0, 0, 0, 36, 96, 73, 56, 234 // field value (156234234090)
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_compact_u64_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_compact_u64(1, 0x100000000);
            bld.add_compact_u64(2, 0xFFFFFFFF);
            bld.add_compact_u64(3, 0xFFFF);
            bld.add_compact_u64(4, 0xFF);
        }
        assert_eq!(
            &[
                0, 0, 0, 4, // field count
                0, 1, // field-tag 1
                0, 0, 0, 8, // field-length
                0, 0, 0, 1, 0, 0, 0, 0, // field-value,
                0, 2, // field-tag 2
                0, 0, 0, 4, // field-length
                255, 255, 255, 255, // field-value
                0, 3, // field-tag 3
                0, 0, 0, 2, // field-length
                255, 255, // field-value
                0, 4, // field-tag 4
                0, 0, 0, 1,   // field-length
                255  // field-value
            ],
            &data[..]
        );
    }

    #[test]
    fn can_add_utf8_to_frame() {
        let mut data = Vec::with_capacity(100);
        {
            let mut bld = FrameBuilder::new(&mut data);
            bld.add_utf8(1022, "hello");
        }
        assert_eq!(
            &[
                0, 0, 0, 1, // field count = 1
                3, 254, // tag = 1022
                0, 0, 0, 5, // field length = 2
                104, 101, 108, 108, 111 // field value (156234234090)
            ],
            &data[..]
        );
    }

    #[test]
    fn can_not_parse_a_frame_if_there_is_not_enough_data_for_field_count() {
        let data = &[0, 0, 0]; // need four bytes for a field count.
        assert_eq!(Some(Error::IncompleteFrameFieldCount), FrameParser::new(data).err());
    }

    #[test]
    fn can_not_parse_a_frame_if_there_is_not_enough_data_for_field_tag_and_length() {
        let data = &[
            0, 0, 0, 1, // field count = 1
            0, 1, // tag = 1
            0, 0, 0 // incomplete field length
        ];
        assert_eq!(Some(Error::IncompleteFieldTagOrLength), FrameParser::new(data).err());
    }

    #[test]
    fn can_not_parse_a_frame_if_there_is_not_enough_data_for_a_field_value() {
        let data = &[
            0, 0, 0, 1, // field count = 1
            0, 1, // tag = 1
            0, 0, 0, 4, // field length = 4
            1, 2, 3 // incomplete value
        ];
        assert_eq!(Some(Error::IncompleteFieldValue(4, 3)), FrameParser::new(data).err());
    }

    #[test]
    fn can_read_data_from_frame() {
        let data = &[
            0, 0, 0, 1, // field count = 1
            0, 1, // tag = 1
            0, 0, 0, 4, // field length = 4
            1, 2, 3, 4 //
        ];
        let frame = FrameParser::new(data).unwrap();
        assert_eq!(&[1, 2, 3, 4], frame.get_data(1).unwrap());
    }
}
