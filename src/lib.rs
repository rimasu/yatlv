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
//! The root frame can either be encoded as a `frame` or as a `packet-frame`.  Encoding
//! as a `packet-frame` is useful when sending `frame`s across a stream.

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
}

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

/// PacketBuilder can be used to push a packet into a mutable Vec<u8>
///
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
        self.data.extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.data.extend_from_slice(value);
    }

    fn add_child(&mut self, tag: u16) -> PacketFrameBuilder {
        self.field_count += 1;
        self.data.reserve(6);
        self.data.extend_from_slice(&tag.to_be_bytes());
        PacketFrameBuilder::new(self.data)
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
                0, 60,  // field-tag in child frame
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
                0, 60,  // field-tag in child frame
                0, 0, 0, 2, // field-length in child frame
                9, 255 // field-value in child frame
            ],
            &data[..]
        );
    }
}
