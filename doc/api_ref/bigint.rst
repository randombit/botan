BigInt
========================================

``BigInt``, in ``bigint.h``, is an implementation of a signed magnitude
multiple-precision integer, which is used to implement certain older public key
algorithms such as RSA. It also appears in other contexts, for example X.509
certificate serial numbers are technically integer values and can be quite
large, and so are represented using a ``BigInt``.

A ``BigInt`` is a sequence of smaller integers of type ``word``; this type is
defined to be either ``uint32_t`` or ``uint64_t``, depending on the word size of
the processor.

.. warning::

   While it is possible to use the APIs provided by ``BigInt`` as a general
   calculation facility, it is **extremely inadvisable** that you attempt to
   implement a cryptographic scheme of any kind directly using ``BigInt``.
   Botan internally has many facilities for fast and side channel safe
   arithmetic which are not exposed to callers.

   In general, as a library user, avoid doing anything with ``BigInt`` besides
   serializing or deserializing them as required to call other interfaces.
   Some of the general calculation facilities of ``BigInt`` may be made internal
   to the library in a future major release.

.. cpp:class:: BigInt

   .. cpp:function:: static BigInt BigInt::from_string(std::string_view str)

      Create a BigInt from a string. By default decimal is expected. With an 0x
      prefix, instead it is treated as hexadecimal. A ``-`` prefix to indicate
      negative numbers is also accepted.

   .. cpp:function:: static BigInt::from_bytes(std::span<const uint8_t> buf)

      Create a BigInt from a binary array (big-endian encoding). The result of
      this function will always be positive; there is no support for a sign bit,
      2s complement encoding, or similar methods for indicating a negative value.

   .. cpp:function:: void serialize_to(std::span<uint8_t> buf)

      Encode this BigInt as a big-endian integer. The sign is ignored.

      There must be sufficient space to encode the entire integer in ``buf``.
      If ``buf`` is larger than required, sufficient zero bytes will be
      prefixed.

   .. cpp:function:: size_t bytes() const

      Return number of bytes needed to represent value of ``*this``

   .. cpp:function:: size_t bits() const

      Return number of bits needed to represent value of ``*this``

   .. cpp:function:: std::string to_dec_string() const

      Encode the integer as a decimal string.

   .. cpp:function:: std::string to_hex_string() const

      Encode the integer as a hexadecimal string, with "0x" prefix

   .. cpp:function:: BigInt::zero()

      Create a BigInt with value zero

   .. cpp:function:: BigInt::from_u64(uint64_t n)

      Create a BigInt with value *n*

   .. cpp:function:: BigInt operator+(const BigInt& x, const BigInt& y)

      Add ``x`` and ``y`` and return result.

   .. cpp:function:: BigInt operator+(const BigInt& x, word y)

      Add ``x`` and ``y`` and return result.

   .. cpp:function:: BigInt operator+(word x, const BigInt& y)

      Add ``x`` and ``y`` and return result.

   .. cpp:function:: BigInt operator-(const BigInt& x, const BigInt& y)

      Subtract ``y`` from ``x`` and return result.

   .. cpp:function:: BigInt operator-(const BigInt& x, word y)

      Subtract ``y`` from ``x`` and return result.

   .. cpp:function:: BigInt operator*(const BigInt& x, const BigInt& y)

      Multiply ``x`` and ``y`` and return result.

   .. cpp:function:: BigInt operator/(const BigInt& x, const BigInt& y)

      Divide ``x`` by ``y`` and return result.

   .. cpp:function:: BigInt operator%(const BigInt& x, const BigInt& y)

      Divide ``x`` by ``y`` and return remainder.

   .. cpp:function:: word operator%(const BigInt& x, word y)

      Divide ``x`` by ``y`` and return remainder.

   .. cpp:function:: word operator<<(const BigInt& x, size_t n)

      Left shift ``x`` by ``n`` and return result.

   .. cpp:function:: word operator>>(const BigInt& x, size_t n)

      Right shift ``x`` by ``n`` and return result.

   .. cpp:function:: BigInt& operator+=(const BigInt& y)

      Add y to ``*this``

   .. cpp:function:: BigInt& operator+=(word y)

      Add y to ``*this``

   .. cpp:function:: BigInt& operator-=(const BigInt& y)

      Subtract y from ``*this``

   .. cpp:function:: BigInt& operator-=(word y)

      Subtract y from ``*this``

   .. cpp:function:: BigInt& operator*=(const BigInt& y)

      Multiply ``*this`` with y

   .. cpp:function:: BigInt& operator*=(word y)

      Multiply ``*this`` with y

   .. cpp:function:: BigInt& operator/=(const BigInt& y)

      Divide ``*this`` by y

   .. cpp:function:: BigInt& operator%=(const BigInt& y)

      Divide ``*this`` by y and set ``*this`` to the remainder.

   .. cpp:function:: word operator%=(word y)

      Divide ``*this`` by y and set ``*this`` to the remainder.

   .. cpp:function:: word operator<<=(size_t shift)

      Left shift ``*this`` by *shift* bits

   .. cpp:function:: word operator>>=(size_t shift)

      Right shift ``*this`` by *shift* bits

   .. cpp:function:: BigInt& operator++()

      Increment ``*this`` by 1

   .. cpp:function:: BigInt& operator--()

      Decrement ``*this`` by 1

   .. cpp:function:: BigInt operator++(int)

      Postfix increment ``*this`` by 1

   .. cpp:function:: BigInt operator--(int)

      Postfix decrement ``*this`` by 1

   .. cpp:function:: BigInt operator-() const

      Negation operator

   .. cpp:function:: bool operator !() const

      Return true unless ``*this`` is zero

   .. cpp:function:: void clear()

      Set ``*this`` to zero

   .. cpp:function:: uint32_t to_u32bit() const

      Return value of ``*this`` as a 32-bit integer, if possible.
      If the integer is negative or not in range, an exception is thrown.

   .. cpp:function:: bool is_even() const

      Return true if ``*this`` is even

   .. cpp:function:: bool is_odd() const

      Return true if ``*this`` is odd

   .. cpp:function:: bool is_nonzero() const

      Return true if ``*this`` is not zero

   .. cpp:function:: bool is_zero() const

      Return true if ``*this`` is zero

   .. cpp:function:: bool is_negative() const

      Return true if ``*this`` is less than zero

   .. cpp:function:: bool is_positive() const

      Return true if ``*this`` is greater than or equal to zero

   .. cpp:function:: BigInt abs() const

      Return absolute value of ``*this``

