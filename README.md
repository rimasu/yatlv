[![Rust](https://github.com/rimasu/yatlv/actions/workflows/rust.yml/badge.svg)](https://github.com/rimasu/yatlv/actions/workflows/rust.yml)
[![Docs](https://docs.rs/yatlv/badge.svg)](https://docs.rs/yatlv)

Yet Another Tag Length Value (YATLV) format.

Tag-length-value formats are a common way to exchange structured data in a compact and
well defined way.  They stand midway between schema-rich formats (like `JSON`, `YAML` and `XML`)
and compact binary formats that contain no schema information (like `bincode`).

One advantage of tag-length-value formats is they support better forwards compatibility
than their schema-less cousins because they contain just enough information for a parser to
skip fields they do not recognise.

Unlike many tag-length-value formats, no attempt is made to use variable length
encodings to reduce the amount of space taken by the 'length'.  This does lead to larger
encodings but simplifies the job of the parser and builder significantly.

Structure of the format:
```abnf
packet-frame = frame-size frame
frame-size   = unsigned32
frame        = frame-format field-count *field
frame-format = 0x01
field-count  = unsigned32
field        = field-tag field-length field-value
field-tag    = unsigned16
field-length = unsigned32
field-value  = octet-array
unsigned16   = 0x0000-0xFFFF
unsigned32   = 0x00000000-0xFFFFFFFF
octet-array  = *0x00-0xFF
```
Where:

* frame-format is always 0x01, but alternative formats may be added later
* the number `field`s must match `field-count`
* the length of `field-value` must match `field-length`.
* `unsigned-16` and `unsigned-32` are encoded using big-endian.

The root frame can either be encoded as a `frame` or as a `packet-frame`.  Encoding
as a `packet-frame` is useful when sending `frame`s across a stream.

Although applications can store arbitrary data in the `field-value`, the following
conventions should normally be observed:

* numbers use big-endian encoding
* boolean values are encoded using a single byte (`0x00`=`false`, `0xFF`=`true`)
* text is encoded as UTF-8

## Reading and Writing

This library tries to make reading and writing reliable and not dependant on
the values being written.  To that end, the `add_*` methods for numbers always
use the same number of bytes, irrespective of the actual values being written.
Currently only `add_data` and `add_str` can add a variable number of bytes to the frame.

Reading attempts to be forward compatible, with the following guarantees:

* Any number written by a smaller `add_u*` method can always be be safely read by a larger one.
(e.g., a number written using `add_u16` can be safely read using`get_u32`).
* Any number written by a larger `add_u*` method can be read by a smaller one _if_ the value
is small enough.

This means that when upgrading a program it should always be safe to increase the range
of a field, but special handling is needed if the range of a field is going to decreased.

```rust
use yatlv::Result;

use yatlv::{FrameBuilder, FrameBuilderLike, FrameParser};

const TAG1: u16 = 1;
const TAG2: u16 = 2;
const TAG3: u16 = 3;
const TAG4: u16 = 4;

// the FrameBuilder will expand the buffer as needed, but it is more
// efficient to allocate enough capacity up front.
let mut buf = Vec::with_capacity(1000);

{
    let mut bld1 = FrameBuilder::new(&mut buf);
    bld1.add_str(TAG1, "hello");

    {
        // child FrameBuilders retain a mutable reference
        // to their parent - so you cannot have two child
        // FrameBuilders in the same scope.
        let mut bld2a = bld1.add_frame(TAG2);
        bld2a.add_u32(TAG4, 78);
        bld2a.add_u32(TAG4, 109);
    }

    {
        let mut bld2b = bld1.add_frame(TAG3);
        bld2b.add_str(TAG4, "goodbye");
    }
}

let parser1 = FrameParser::new(&buf)?;
assert_eq!(Some("hello"), parser1.get_str(TAG1)?);

// FrameParsers only have an immutable reference to their parent,
// so you can hold references to multiple child frames when parsing.
let parser2a = parser1.get_frame(TAG2)?.unwrap();
let parser2b = parser1.get_frame(TAG3)?.unwrap();

// Here we are using iterator access to get all the values with the same tag (TAG4)
let frame2a_values: Vec<_> = parser2a.get_u32s(TAG4).map(|v| v.unwrap()).collect();
assert_eq!(vec![78, 109], frame2a_values);

let frame2b_value = parser2b.get_str(TAG4)?;
assert_eq!(Some("goodbye"), frame2b_value);

```

This is a hobby project; I don't have the bandwidth
to properly maintain this.  You are welcome to use
and fork at your risk, but I would not recommend this
crate for any serious work.

Current version: 1.0.1

License: MIT/Apache-2.0
