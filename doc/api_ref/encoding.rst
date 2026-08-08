Binary-to-Text Encodings
========================================

Botan provides routines for encoding binary data as printable text and decoding
back again. Four encodings are supported: hex, base64, base32, and base58 (the
last with an optional 4-byte checksum). Each lives in its own header.

The hex, base32, and base64 encodings and decoding algorithms are constant time
with respect to their input values. Currently the base58 radix conversion code
is not completely constant time, and may leak some information about the contents.

Hex
----------------------------------------

Defined in ``botan/hex.h``. Hex encoding represents each input byte as a pair of
hexadecimal digits, doubling the input length.

.. cpp:function:: void hex_encode(char output[], const uint8_t input[], \
                                  size_t input_length, bool uppercase = true)

   Hex-encode ``input_length`` bytes from ``input`` into ``output``, which must
   have room for at least ``2 * input_length`` characters. The output is not
   null-terminated. If ``uppercase`` is true (the default) the digits ``A``
   through ``F`` are used, otherwise ``a`` through ``f``.

.. cpp:function:: std::string hex_encode(const uint8_t input[], size_t input_length, \
                                         bool uppercase = true)
.. cpp:function:: std::string hex_encode(std::span<const uint8_t> input, \
                                         bool uppercase = true)

   Return the hex encoding of ``input`` as a ``std::string``.

.. cpp:function:: size_t hex_decode(uint8_t output[], const char input[], \
                                    size_t input_length, size_t& input_consumed, \
                                    bool ignore_ws = true)

   Decode hex-encoded ``input`` into ``output``, which must have room for at
   least ``input_length / 2`` bytes. Returns the number of bytes written to
   ``output``. ``input_consumed`` is set to the number of input characters
   actually consumed; if less than ``input_length`` the remaining input
   (an odd trailing nibble) should be passed in along with more input on the
   next call. If ``ignore_ws`` is true, whitespace in the input is skipped;
   otherwise an exception is thrown on whitespace. Throws
   ``Invalid_Argument`` if a non-hex, non-whitespace character is encountered.

.. cpp:function:: size_t hex_decode(uint8_t output[], const char input[], \
                                    size_t input_length, bool ignore_ws = true)
.. cpp:function:: size_t hex_decode(uint8_t output[], std::string_view input, \
                                    bool ignore_ws = true)
.. cpp:function:: size_t hex_decode(std::span<uint8_t> output, std::string_view input, \
                                    bool ignore_ws = true)

   Decode ``input`` into ``output`` and return the number of bytes written.
   ``Invalid_Argument`` is thrown if the input is not a whole number of hex
   digits (after whitespace is stripped, if enabled) or contains an invalid
   character.

.. cpp:function:: std::vector<uint8_t> hex_decode(const char input[], \
                                                  size_t input_length, \
                                                  bool ignore_ws = true)
.. cpp:function:: std::vector<uint8_t> hex_decode(std::string_view input, \
                                                  bool ignore_ws = true)

   Decode ``input`` and return the result as a ``std::vector<uint8_t>``.

.. cpp:function:: secure_vector<uint8_t> hex_decode_locked(const char input[], \
                                                           size_t input_length, \
                                                           bool ignore_ws = true)
.. cpp:function:: secure_vector<uint8_t> hex_decode_locked(std::string_view input, \
                                                           bool ignore_ws = true)

   Like :cpp:func:`hex_decode`, but returns a :doc:`secure_vector <secmem>`
   so the buffer is zeroed before being freed.

Base64
----------------------------------------

Defined in ``botan/base64.h``. Base64 encoding (:rfc:`4648`) maps every three
input bytes to four ASCII characters drawn from
``A-Z``, ``a-z``, ``0-9``, ``+`` and ``/``, with ``=`` used as a padding
character when the input length is not a multiple of three.

.. cpp:function:: size_t base64_encode(char output[], const uint8_t input[], \
                                       size_t input_length, size_t& input_consumed, \
                                       bool final_inputs)

   Encode ``input_length`` bytes of ``input`` into ``output``, which must be at
   least :cpp:func:`base64_encode_max_output` bytes. Returns the number of
   characters written. If ``final_inputs`` is true the encoding is finalized,
   including any necessary ``=`` padding; otherwise only complete 3-byte groups
   are encoded and the number of bytes consumed is reported in
   ``input_consumed`` so the remainder can be supplied with the next call.

.. cpp:function:: std::string base64_encode(const uint8_t input[], size_t input_length)
.. cpp:function:: std::string base64_encode(std::span<const uint8_t> input)

   Return the base64 encoding of ``input`` as a ``std::string``.

.. cpp:function:: size_t base64_decode(uint8_t output[], const char input[], \
                                       size_t input_length, size_t& input_consumed, \
                                       bool final_inputs, bool ignore_ws = true)

   Decode base64 ``input`` into ``output``, which must be at least
   :cpp:func:`base64_decode_max_output` bytes. Returns the number of bytes
   written. As with :cpp:func:`base64_encode`, ``final_inputs`` controls whether
   the call finalizes the decoding (allowing ``=`` padding) or processes only
   complete 4-character groups. Throws ``Invalid_Argument`` on invalid input,
   such as data following padding or nonzero padding bits. Excess trailing
   ``=`` characters are currently ignored.

.. cpp:function:: size_t base64_decode(uint8_t output[], const char input[], \
                                       size_t input_length, bool ignore_ws = true)
.. cpp:function:: size_t base64_decode(uint8_t output[], std::string_view input, \
                                       bool ignore_ws = true)
.. cpp:function:: size_t base64_decode(std::span<uint8_t> output, \
                                       std::string_view input, bool ignore_ws = true)

   Decode ``input`` into ``output`` and return the number of bytes written.

.. cpp:function:: secure_vector<uint8_t> base64_decode(const char input[], \
                                                       size_t input_length, \
                                                       bool ignore_ws = true)
.. cpp:function:: secure_vector<uint8_t> base64_decode(std::string_view input, \
                                                       bool ignore_ws = true)

   Decode ``input`` and return the result as a :doc:`secure_vector <secmem>`.

.. cpp:function:: size_t base64_encode_max_output(size_t input_length)

   Return an upper bound on the number of characters that
   :cpp:func:`base64_encode` will produce for an input of ``input_length`` bytes.

.. cpp:function:: size_t base64_decode_max_output(size_t input_length)

   Return an upper bound on the number of bytes that :cpp:func:`base64_decode`
   will produce for an input of ``input_length`` characters.

Base32
----------------------------------------

Defined in ``botan/base32.h``. Base32 encoding (:rfc:`4648`) maps every five
input bytes to eight ASCII characters drawn from ``A-Z`` and ``2-7``, with
``=`` used as a padding character. It is less compact than base64 but is useful
in contexts with case-insensitive text, such as DNS labels. Botan produces and
accepts only the uppercase alphabet.

.. cpp:function:: size_t base32_encode(char output[], const uint8_t input[], \
                                       size_t input_length, size_t& input_consumed, \
                                       bool final_inputs)

   Encode ``input_length`` bytes of ``input`` into ``output``, which must be at
   least :cpp:func:`base32_encode_max_output` bytes. Returns the number of
   characters written. If ``final_inputs`` is true the encoding is finalized
   with any necessary ``=`` padding; otherwise only complete 5-byte groups are
   encoded. ``input_consumed`` reports the number of bytes consumed, so the
   unused tail begins at that offset.

.. cpp:function:: std::string base32_encode(const uint8_t input[], size_t input_length)
.. cpp:function:: std::string base32_encode(std::span<const uint8_t> input)

   Return the base32 encoding of ``input`` as a ``std::string``. The output
   uses the uppercase RFC 4648 alphabet.

.. cpp:function:: size_t base32_decode(uint8_t output[], const char input[], \
                                       size_t input_length, size_t& input_consumed, \
                                       bool final_inputs, bool ignore_ws = true)

   Decode base32 ``input`` into ``output``, which must be at least
   :cpp:func:`base32_decode_max_output` bytes. Returns the number of bytes
   written. ``final_inputs`` controls whether the call finalizes decoding
   (allowing ``=`` padding) or only processes complete 8-character groups.
   Throws ``Invalid_Argument`` on invalid input.

.. cpp:function:: size_t base32_decode(uint8_t output[], const char input[], \
                                       size_t input_length, bool ignore_ws = true)
.. cpp:function:: size_t base32_decode(uint8_t output[], std::string_view input, \
                                       bool ignore_ws = true)

   Decode ``input`` into ``output`` and return the number of bytes written.

.. cpp:function:: secure_vector<uint8_t> base32_decode(const char input[], \
                                                       size_t input_length, \
                                                       bool ignore_ws = true)
.. cpp:function:: secure_vector<uint8_t> base32_decode(std::string_view input, \
                                                       bool ignore_ws = true)

   Decode ``input`` and return the result as a :doc:`secure_vector <secmem>`.

.. cpp:function:: size_t base32_encode_max_output(size_t input_length)

   Return an upper bound on the number of characters that
   :cpp:func:`base32_encode` will produce for an input of ``input_length`` bytes.

.. cpp:function:: size_t base32_decode_max_output(size_t input_length)

   Return an upper bound on the number of bytes that :cpp:func:`base32_decode`
   will produce for an input of ``input_length`` characters.

Base58
----------------------------------------

Defined in ``botan/base58.h``. Base58 is a variable-length, non-padded encoding
originally introduced by Bitcoin. The alphabet is

::

   123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

The characters ``0`` (zero), ``O`` (uppercase oh), ``I`` (uppercase i), and
``l`` (lowercase L) are omitted to reduce the chance of transcription errors.
Each leading zero byte of the input is encoded as a leading ``1`` character of
the output.

Two variants are provided: a raw encoding, and a *checked* encoding that
appends a 4-byte checksum equal to the first four bytes of ``SHA-256(SHA-256(input))``
to the input before encoding. The checked form is what is commonly meant by
"base58" in cryptocurrency contexts.

.. cpp:function:: std::string base58_encode(const uint8_t input[], size_t input_length)
.. cpp:function:: std::string base58_encode(std::span<const uint8_t> input)

   Return the raw base58 encoding of ``input``. No checksum is included.

.. cpp:function:: std::string base58_check_encode(const uint8_t input[], size_t input_length)
.. cpp:function:: std::string base58_check_encode(std::span<const uint8_t> input)

   Append a 4-byte ``SHA-256(SHA-256(input))`` checksum to ``input`` and return
   the base58 encoding of the result.

.. cpp:function:: std::vector<uint8_t> base58_decode(const char input[], size_t input_length)
.. cpp:function:: std::vector<uint8_t> base58_decode(std::string_view input)

   Decode raw base58 ``input``. Whitespace (space and newline) in the input is
   ignored. Throws ``Decoding_Error`` if the input contains a character outside
   the base58 alphabet.

.. cpp:function:: std::vector<uint8_t> base58_check_decode(const char input[], size_t input_length)
.. cpp:function:: std::vector<uint8_t> base58_check_decode(std::string_view input)

   Decode base58 ``input``, verify the trailing 4-byte checksum, and return the
   decoded payload with the checksum stripped. Throws ``Decoding_Error`` if the
   input is shorter than 4 bytes after decoding, contains an invalid
   character, or the checksum does not match.
