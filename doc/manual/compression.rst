Lossless Data Compression
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some lossless data compression algorithms are available in botan, currently all
via third party libraries - these include zlib (including deflate and gzip
formats), bzip2, and lzma.

.. note::
   You should always compress *before* you encrypt, because encryption seeks to
   hide the redundancy that compression is supposed to try to find and remove.

All compressors provide the `Transform` interface through a subclass
`Compression_Transform` (defined in compression.h). The compression algorithms
have some limitations in terms of the standard API, in particular the
`output_length` function simply throws an exception since the value cannot be
determined merely from the input length for such an algorithm.

The transformations work much like any other - calling `update` on a vector
returns the (de)compressed result, calling `finish` completes the computation.
All (de)compression algorithms will accept inputs of any size
(update_granularity is 1) and do not require any final data be saved to be
passed to `finish`.

On `Compression_Transform` an additional function function `flush` is available
which (in addition to always acting as equivalent to an `update`) signals the
compression function to flush as much output as possible immediately, regardless
of considerations of compression ratio. Any compressor or decompressor may
ignore this and treat it as equivalent to a normal update.

The easiest way to get a compressor is via the functions

.. cpp:function:: Compression_Transform* make_compressor(std::string type, size_t level)
.. cpp:function:: Compression_Transform* make_decompressor(std::string type)

Supported values for `type` include `zlib` (raw zlib with no checksum),
`deflate` (zlib's deflate format), `gzip`, `bz2`, and `lzma`. A null pointer
will be returned if the algorithm is unavailable. The meaning of the `level`
parameter varies by the algorithm but generally takes a value between 1 and 9,
with higher values implying typically better compression from and more memory
and/or CPU time consumed by the compression process. The decompressor can always
handle input from any compressor.

As with any consumer of complex formats, a decompressor may throw an exception
(from either `update` or `finish`) if the input is invalid or corrupt.

To use a compression algorithm in a `Pipe` use the adaptor types
`Compression_Filter` and `Decompression_Filter` from `comp_filter.h`. The
constructors of both filters take a `std::string` argument (passed to
`make_compressor` or `make_decompressor`), the compression filter also takes a
`level` parameter. Finally both constructors have a parameter `buf_sz` which
specifies the size of the internal buffer that will be used - inputs will be
broken into blocks of this size. The default is 4096.
