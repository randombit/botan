Lossless Data Compression
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some lossless data compression algorithms are available in botan, currently all
via third party libraries - these include zlib (including deflate and gzip
formats), bzip2, and lzma. Support for these must be enabled at build time;
you can check for them using the macros ``BOTAN_HAS_ZLIB``, ``BOTAN_HAS_BZIP2``,
and ``BOTAN_HAS_LZMA``.

.. note::
   You should always compress *before* you encrypt, because encryption seeks to
   hide the redundancy that compression is supposed to try to find and remove.

Compression is done through the ``Compression_Algorithm`` and
``Decompression_Algorithm`` classes, both defined in `compression.h`

Compression and decompression both work in three stages: starting a
message (``start``), continuing to process it (``update``), and then
finally completing processing the stream (``finish``).

The easiest way to get a compressor is via the functions
``Compression_Algorithm::create`` and
``Decompression_Algorithm::create`` which both accept a string
argument which can take values include `zlib` (raw zlib with no
checksum), `deflate` (zlib's deflate format), `gzip`, `bz2`, and
`lzma`. A null pointer will be returned if the algorithm is
unavailable.

API Overview
------------

.. container:: toggle

   .. doxygenclass:: Botan::Compression_Algorithm
      :members: start,update,finish

   .. doxygenclass:: Botan::Decompression_Algorithm
      :members: start,update,finish

To use a compression algorithm in a `Pipe` use the adapter types
`Compression_Filter` and `Decompression_Filter` from `comp_filter.h`. The
constructors of both filters take a `std::string` argument (passed to
`make_compressor` or `make_decompressor`), the compression filter also takes a
`level` parameter. Finally both constructors have a parameter `buf_sz` which
specifies the size of the internal buffer that will be used - inputs will be
broken into blocks of this size. The default is 4096.
