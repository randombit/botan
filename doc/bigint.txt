BigInt
========================================

``BigInt`` is Botan's implementation of a multiple-precision
integer. Thanks to C++'s operator overloading features, using
``BigInt`` is often quite similar to using a native integer type. The
number of functions related to ``BigInt`` is quite large. You can find
most of them in ``botan/bigint.h`` and ``botan/numthry.h``.

.. note::

  If you can, always use expressions of the form ``a += b`` over ``a =
  a + b``. The difference can be *very* substantial, because the first
  form prevents at least one needless memory allocation, and possibly
  as many as three. This will be less of an issue once the library
  adopts use of C++0x's rvalue references.

Encoding Functions
----------------------------------------

These transform the normal representation of a ``BigInt`` into some
other form, such as a decimal string:

.. cpp:function:: SecureVector<byte> BigInt::encode(const BigInt& n, Encoding enc = Binary)

  This function encodes the BigInt n into a memory
  vector. ``Encoding`` is an enum that has values ``Binary``,
  ``Octal``, ``Decimal``, and ``Hexadecimal``.

.. cpp:function:: BigInt BigInt::decode(const MemoryRegion<byte>& vec, Encoding enc)

  Decode the integer from ``vec`` using the encoding specified.

These functions are static member functions, so they would be called
like this::

  BigInt n1 = ...; // some number
  SecureVector<byte> n1_encoded = BigInt::encode(n1);
  BigInt n2 = BigInt::decode(n1_encoded);
  assert(n1 == n2);

There are also C++-style I/O operators defined for use with
``BigInt``. The input operator understands negative numbers,
hexadecimal numbers (marked with a leading "0x"), and octal numbers
(marked with a leading '0'). The '-' must come before the "0x" or '0'
marker. The output operator will never adorn the output; for example,
when printing a hexadecimal number, there will not be a leading "0x"
(though a leading '-' will be printed if the number is negative). If
you want such things, you'll have to do them yourself.

``BigInt`` has constructors that can create a ``BigInt`` from an
unsigned integer or a string. You can also decode an array (a ``byte``
pointer plus a length) into a ``BigInt`` using a constructor.

Number Theory
----------------------------------------

Number theoretic functions available include:

.. cpp:function:: BigInt gcd(BigInt x, BigInt y)

  Returns the greatest common divisor of x and y

.. cpp:function:: BigInt lcm(BigInt x, BigInt y)

  Returns an integer z which is the smallest integer such that z % x
  == 0 and z % y == 0

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

.. cpp:function:: bool quick_check_prime(BigInt n, RandomNumberGenerator& rng)

.. cpp:function:: bool check_prime(BigInt n, RandomNumberGenerator& rng)

.. cpp:function:: bool verify_prime(BigInt n, RandomNumberGenerator& rng)

  Three variations on primality testing. All take an integer to test along with
  a random number generator, and return true if the integer seems like it might
  be prime; there is a chance that this function will return true even with
  a composite number. The probability decreases with the amount of work performed,
  so it is much less likely that ``verify_prime`` will return a false positive
  than ``check_prime`` will.

.. cpp:function BigInt random_prime(RandomNumberGenerator& rng, \
   size_t bits, BigInt coprime = 1, size_t equiv = 1, size_t equiv_mod = 2)

  Return a random prime number of ``bits`` bits long that is
  relatively prime to ``coprime``, and equivalent to ``equiv`` modulo
  ``equiv_mod``.

