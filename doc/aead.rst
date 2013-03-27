AEAD Modes
========================================

AEAD (Authenticated Encryption with Associated Data) modes provide
message encryption, message authentication, and the ability to
authenticate additional data that is not included in the ciphertext
(such as a sequence number or header).

The AEAD interface can be used directly, or as part of the filter
system by using :cpp:class:`AEAD_Filter`.

AEAD modes currently available include GCM, OCB, and EAX.

.. cpp:class:: AEAD_Mode

  .. cpp:function:: void set_key(const SymmetricKey& key)

       Set the key

  .. cpp:function:: Key_Length_Specification key_spec() const

       Return the key length specification

  .. cpp:function:: void set_associated_data(const byte ad[], size_t ad_len)

       Set any associated data for this message. For maximum
       portability between different modes, this must be called after
       :cpp:func:`set_key` and before :cpp:func:`start`.

       If the associated data does not change, it is not necessary to
       call this function more than once, even across multiple calls
       to :cpp:func:`start` and :cpp:func:`finish`.

  .. cpp:function:: secure_vector<byte> start(const byte nonce[], size_t nonce_len)

       Start processing a message, using *nonce* as the unique
       per-message value.

       Returns any initial data that should be emitted (such as a header).

  .. cpp:function:: void update(secure_vector<byte>& buffer)

       Continue processing a message. The *buffer* is an in/out
       parameter and may be resized. In particular, some modes require
       that all input be consumed before any output is produced; with
       these modes, *buffer* will be returned resized to 0.

  .. cpp:function:: void finish(secure_vector<byte>& buffer)

       Complete processing a message with a final input of *buffer*,
       which is treated the same as with :cpp:func:`update`. The
       *buffer* is an in/out parameter. On input it contains any final
       part of the message that needs to be processed. On output it
       contains any final output.

       Note that if you have the entire message in hand, calling
       finish with the entire message (without ever calling update) is
       both efficient and convenient.

  .. cpp:function:: size_t update_granularity() const

       The AEAD interface requires :cpp:func:`update` be called
       with at least this many bytes.

  .. cpp:function:: size_t final_minimum_size() const

       The AEAD interface requires :cpp:func:`finish` be called
       with at least this many bytes.

  .. cpp:function:: bool valid_nonce_length(size_t nonce_len) const

       Returns true if *nonce_len* is a valid nonce length for this
       scheme. For EAX and GCM, any length nonces are allowed. OCB
       allows any value between 8 and 15 bytes.
