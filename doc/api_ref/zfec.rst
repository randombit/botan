ZFEC Forward Error Correction
===============================

.. versionadded:: 3.0.0

The ``ZFEC`` class provides forward error correction compatible
with the `zfec <https://github.com/tahoe-lafs/zfec>`_ library.

Forward error correction takes an input and creates multiple "shares",
such that any ``K`` of ``N`` shares is sufficient to recover the
entire original input.

.. note::
   Specific to the ZFEC format, the first ``K`` generated shares
   are identical to the original input data, followed by ``N-K``
   shares of error correcting code.

``ZFEC`` requires that the input length be exactly divisible by ``K``;
if needed define a padding scheme to pad your input to the necessary
size.

.. cpp:class:: ZFEC

  .. cpp:function:: ZFEC(size_t k, size_t n)

     Set up for encoding or decoding using parameters ``k`` and ``n``.
     Both must be less than 256, and ``k`` must be less than ``n``.

  .. cpp:function:: void encode(const uint8_t input[], size_t size, \
         std::function<void (size_t, size_t, const uint8_t[], size_t)> output_cb) const

     Encode ``input`` of total length ``size`` into ``N`` shares. The ``output_cb``
     function will be called once for each share (in unspecified order).

     The parameters to ``output_cb`` are: the current share, the maximum share (this
     will always be ``K``), and the value and length of the share.

  .. cpp:function:: void decode(const std::map<size_t, const uint8_t*>& shares, \
         size_t share_size, \
         std::function<void (size_t, size_t, const uint8_t[], size_t)> output_cb) const

     Decode some set of shares into the original input. Each share is
     of ``share_size`` bytes. The shares are identified by a small
     integer (between 0 and 255).

     The parameters to ``output_cb`` are similar to that of ``encode``.

