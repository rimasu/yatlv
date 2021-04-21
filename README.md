# yatlv

Yet Another Tag Length Value (YATLV) format.

Tag-length-value formats are a common way to exchange structured data in a compact and
well defined way.  They stand midway between schema rich formats (like `JSON`, `YAML` and `XML`)
and compact binary formats that contain no schema information (like `bincode`).

One advantage of tag-length-value formats is they support better forwards compatibility
than their schema less cousins because they contain just enough information for a parser to
skip fields they do not recognise.

Unlike many tag-length-value formats no attempt is made to use variable length
encodings to reduce the amount of space taken by the 'length'.  This does lead to larger
encodings but simplifies the job of the parser and builder significantly.

Structure of the format:
```abnf
packet-frame = frame-size frame
frame-size   = unsigned32
frame        = field-count *field
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

* the number `field`s must match `field-count`
* the length of `field-value` must match `field-length`.
* `unsigned-16` and `unsigned-32` are encoded using big-endian.

The root frame can either be encoded as a `frame` or as a `packet-frame`.  Encoding
as a `packet-frame` is useful when sending `frame`s across a stream.

Although applications can store arbitrary data in `field-value` the follow
conventions should normally be observed:

* numbers use big-endian encoding
* boolean values are encoded using a single byte (`0x00`=`false`, `0xFF`=`true`)
* text is encoded as UTF-8

