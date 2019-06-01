BigInt
========================================

``BigInt`` is Botan's implementation of a multiple-precision integer. Thanks to
C++'s operator overloading features, using ``BigInt`` is often quite similar to
using a native integer type. The number of functions related to ``BigInt`` is
quite large, and not all of them are documented here. You can find the complete
declarations in ``botan/bigint.h`` and ``botan/numthry.h``.

.. cpp:class:: BigInt

   .. cpp:function:: BigInt()

      Create a BigInt with value zero

   .. cpp:function:: BigInt(uint64_t n)

      Create a BigInt with value *n*

   .. cpp:function:: BigInt(const std::string& str)

      Create a BigInt from a string. By default decimal is expected. With an 0x
      prefix instead it is treated as hexadecimal.

   .. cpp:function:: BigInt(const uint8_t buf[], size_t length)

      Create a BigInt from a binary array (big-endian encoding).

   .. cpp:function:: BigInt(RandomNumberGenerator& rng, size_t bits, bool set_high_bit = true)

      Create a random BigInt of the specified size.

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

   .. cpp:function:: size_t bytes() const

      Return number of bytes need to represent value of ``*this``

   .. cpp:function:: size_t bits() const

      Return number of bits need to represent value of ``*this``

   .. cpp:function:: bool is_even() const

      Return true if ``*this`` is even

   .. cpp:function:: bool is_odd() const

      Return true if ``*this`` is odd

   .. cpp:function:: bool is_nonzero() const

      Return true if ``*this`` is not zero

   .. cpp:function:: bool is_zero() const

      Return true if ``*this`` is zero

   .. cpp:function:: void set_bit(size_t n)

      Set bit *n* of ``*this``

   .. cpp:function:: void clear_bit(size_t n)

      Clear bit *n* of ``*this``

   .. cpp:function:: bool get_bit(size_t n) const

      Get bit *n* of ``*this``

   .. cpp:function:: uint32_t to_u32bit() const

      Return value of ``*this`` as a 32-bit integer, if possible.
      If the integer is negative or not in range, an exception is thrown.

   .. cpp:function:: bool is_negative() const

      Return true if ``*this`` is negative

   .. cpp:function:: bool is_positive() const

      Return true if ``*this`` is negative

   .. cpp:function:: BigInt abs() const

      Return absolute value of ``*this``

   .. cpp:function:: void binary_encode(uint8_t buf[]) const

      Encode this BigInt as a big-endian integer. The sign is ignored.

   .. cpp:function:: void binary_encode(uint8_t buf[], size_t len) const

      Encode this BigInt as a big-endian integer. The sign is ignored.
      If ``len`` is less than ``bytes()`` then only the low ``len``
      bytes are output. If ``len`` is greater than ``bytes()`` then
      the output is padded with leading zeros.

   .. cpp:function:: void binary_decode(uint8_t buf[])

      Decode this BigInt as a big-endian integer.

   .. cpp:function:: std::string to_dec_string() const

      Encode the integer as a decimal string.

   .. cpp:function:: std::string to_hex_string() const

      Encode the integer as a hexadecimal string.

Number Theory
----------------------------------------

Number theoretic functions available include:

.. cpp:function:: BigInt gcd(BigInt x, BigInt y)

  Returns the greatest common divisor of x and y

.. cpp:function:: BigInt lcm(BigInt x, BigInt y)

  Returns an integer z which is the smallest integer such that z % x
  == 0 and z % y == 0

.. cpp:function:: BigInt jacobi(BigInt a, BigInt n)

  Return Jacobi symbol of (a|n).

.. cpp:function:: BigInt inverse_mod(BigInt x, BigInt m)

  Returns the modular inverse of x modulo m, that is, an integer
  y such that (x*y) % m == 1. If no such y exists, returns zero.

.. cpp:function:: BigInt power_mod(BigInt b, BigInt x, BigInt m)

  Returns b to the xth power modulo m. If you are doing many
  exponentiations with a single fixed modulus, it is faster to use a
  ``Power_Mod`` implementation.

.. cpp:function:: BigInt ressol(BigInt x, BigInt p)

  Returns the square root modulo a prime, that is, returns a number y
  such that (y*y) % p == x. Returns -1 if no such integer exists.

.. cpp:function:: bool is_prime(BigInt n, RandomNumberGenerator& rng, \
                                size_t prob = 56, double is_random = false)

  Test *n* for primality using a probabilistic algorithm (Miller-Rabin).  With
  this algorithm, there is some non-zero probability that true will be returned
  even if *n* is actually composite. Modifying *prob* allows you to decrease the
  chance of such a false positive, at the cost of increased runtime. Sufficient
  tests will be run such that the chance *n* is composite is no more than 1 in
  2\ :sup:`prob`. Set *is_random* to true if (and only if) *n* was randomly
  chosen (ie, there is no danger it was chosen maliciously) as far fewer tests
  are needed in that case.

.. cpp:function:: BigInt random_prime(RandomNumberGenerator& rng, \
                                      size_t bits, \
                                      BigInt coprime = 1, \
                                      size_t equiv = 1, \
                                      size_t equiv_mod = 2)

  Return a random prime number of ``bits`` bits long that is
  relatively prime to ``coprime``, and equivalent to ``equiv`` modulo
  ``equiv_mod``.
