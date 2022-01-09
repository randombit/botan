ZFEC Forward Error Correction
===============================

.. versionadded:: 3.0.0

The ``ZFEC`` class provides forward error correction compatible
with the `zfec <https://github.com/tahoe-lafs/zfec>`_ library.

Forward error correction takes an input and creates multiple "shares",
such that any ``K`` of ``N`` shares is sufficient to recover the
entire original input.

.. note::
   Specific to the ZFEC format, the first ``K`` generated shares are
   identical to the original input data, followed by ``N-K`` shares of
   error correcting code. This is very different from threshold secret
   sharing, where having fewer than ``K`` shares gives no information
   about the original input.

.. warning::
   If a corrupted share is provided to the decoding algorithm, the
   resulting decoding will be invalid. It is recommended to protect
   shares using a technique such as a MAC or public key signature, if
   corruption is likely in your application.

``ZFEC`` requires that the input length be exactly divisible by ``K``;
if needed define a padding scheme to pad your input to the necessary
size.

An example application that adds padding and a hash checksum is available
in ``src/cli/zfec.cpp`` and invokable using ``botan fec_encode`` and
``botan fec_decode``.

.. cpp:class:: ZFEC

  .. cpp:function:: ZFEC(size_t k, size_t n)

     Set up for encoding or decoding using parameters ``k`` and ``n``.
     Both must be less than 256, and ``k`` must be less than ``n``.

  .. cpp:function:: void encode_shares(const std::vector<const uint8_t*>& shares, \
         size_t share_size, \
         std::function<void (size_t, const uint8_t[], size_t)> output_cb) const

     Encode ``K`` shares in ``shares`` each of length ``share_size`` into ``N``
     shares, also each of length ``share_size``. The ``output_cb`` function will
     be called once for each output share (in some unspecified and possibly
     non-deterministic order).

     The parameters to ``output_cb`` are: the share being output, the share
     contents, and the length of the encoded share (which will always be
     equal to ``share_size``).

  .. cpp:function:: void decode_shares(const std::map<size_t, const uint8_t*>& shares, \
         size_t share_size, \
         std::function<void (size_t, const uint8_t[], size_t)> output_cb) const

     Decode some set of shares into the original input. Each share is
     of ``share_size`` bytes. The shares are identified by a small
     integer (between 0 and 255).

     The parameters to ``output_cb`` are similar to that of ``encode_shares``.
