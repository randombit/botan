AEAD Modes
========================================

.. versionadded:: 1.11.3

AEAD (Authenticated Encryption with Associated Data) modes provide message
encryption, message authentication, and the ability to authenticate additional
data that is not included in the ciphertext (such as a sequence number or
header). It is a subclass of :cpp:class:`Symmetric_Algorithm`.

The AEAD interface can be used directly, or as part of the filter system by
using :cpp:class:`AEAD_Filter` (a subclass of :cpp:class:`Keyed_Filter` which
will be returned by :cpp:func:`get_cipher` if the named cipher is an AEAD mode).

AEAD modes currently available include GCM, OCB, EAX, SIV and CCM. All
support a 128-bit block cipher such as AES. EAX and SIV also support
256 and 512 bit block ciphers.

.. cpp:class:: AEAD_Mode

  .. cpp:function:: void set_key(const SymmetricKey& key)

       Set the key

  .. cpp:function:: Key_Length_Specification key_spec() const

       Return the key length specification

  .. cpp:function:: void set_associated_data(const byte ad[], size_t ad_len)

       Set any associated data for this message. For maximum portability between
       different modes, this must be called after :cpp:func:`set_key` and before
       :cpp:func:`start`.

       If the associated data does not change, it is not necessary to call this
       function more than once, even across multiple calls to :cpp:func:`start`
       and :cpp:func:`finish`.

  .. cpp:function:: void start(const byte nonce[], size_t nonce_len)

       Start processing a message, using *nonce* as the unique per-message
       value.

  .. cpp:function:: void update(secure_vector<byte>& buffer, size_t offset = 0)

       Continue processing a message. The *buffer* is an in/out parameter and
       may be resized. In particular, some modes require that all input be
       consumed before any output is produced; with these modes, *buffer* will
       be returned empty.

       On input, the buffer must be sized in blocks of size
       :cpp:func:`update_granularity`. For instance if the update granularity
       was 64, then *buffer* could be 64, 128, 192, ... bytes.

       The first *offset* bytes of *buffer* will be ignored (this allows in
       place processing of a buffer that contains an initial plaintext header)

  .. cpp:function:: void finish(secure_vector<byte>& buffer, size_t offset = 0)

       Complete processing a message with a final input of *buffer*, which is
       treated the same as with :cpp:func:`update`. It must contain at least
       :cpp:func:`final_minimum_size` bytes.

       Note that if you have the entire message in hand, calling finish without
       ever calling update is both efficient and convenient.

       .. note::
          During decryption, finish will throw an instance of Integrity_Failure
          if the MAC does not validate. If this occurs, all plaintext previously
          output via calls to update must be destroyed and not used in any
          way that an attacker could observe the effects of.

          One simply way to assure this could never happen is to never
          call update, and instead always marshall the entire message
          into a single buffer and call finish on it when decrypting.

  .. cpp:function:: size_t update_granularity() const

       The AEAD interface requires :cpp:func:`update` be called with blocks of
       this size. This will be 1, if the mode can process any length inputs.

  .. cpp:function:: size_t final_minimum_size() const

       The AEAD interface requires :cpp:func:`finish` be called with at least
       this many bytes (which may be zero, or greater than
       :cpp:func:`update_granularity`)

  .. cpp:function:: bool valid_nonce_length(size_t nonce_len) const

       Returns true if *nonce_len* is a valid nonce length for this scheme. For
       EAX and GCM, any length nonces are allowed. OCB allows any value between
       8 and 15 bytes.

  .. cpp:function:: size_t default_nonce_length() const

       Returns a reasonable length for the nonce, typically either 96
       bits, or the only supported length for modes which don't
       support 96 bit nonces.
