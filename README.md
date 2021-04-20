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
packet       = frame-size frame
frame-size   = unsigned32
frame        = field-count *field
field-count  = unsigned32
field        = field-tag field-length field-value
field-tag    = unsigned16
field-length = unsigned32
field-value  = octet-array
unsigned16   = %x0000-xFFFF
unsigned32   = %x00000000-xFFFFFFFF
octet-array  = *%x00-xFF
```
Where:

* the number `field`s must match `field-count`
* the length of `field-value` must match `field-length`.
* `unsigned-16` and `unsigned-32` are encoded using big-endian.

The root frame can either be encoded as a `frame` or as a `packet`.  Encoding
as a `packet` is useful when sending `frame`s across a stream.
