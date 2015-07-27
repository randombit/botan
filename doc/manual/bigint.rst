BigInt
========================================

``BigInt`` is Botan's implementation of a multiple-precision
integer. Thanks to C++'s operator overloading features, using
``BigInt`` is often quite similar to using a native integer type. The
number of functions related to ``BigInt`` is quite large. You can find
most of them in ``botan/bigint.h`` and ``botan/numthry.h``.

Encoding Functions
----------------------------------------

These transform the normal representation of a ``BigInt`` into some
other form, such as a decimal string:

.. cpp:function:: secure_vector<byte> BigInt::encode(const BigInt& n, Encoding enc = Binary)

  This function encodes the BigInt n into a memory
  vector. ``Encoding`` is an enum that has values ``Binary``,
  ``Decimal``, and ``Hexadecimal``.

.. cpp:function:: BigInt BigInt::decode(const std::vector<byte>& vec, Encoding enc)

  Decode the integer from ``vec`` using the encoding specified.

These functions are static member functions, so they would be called
like this::

  BigInt n1 = ...; // some number
  secure_vector<byte> n1_encoded = BigInt::encode(n1);
  BigInt n2 = BigInt::decode(n1_encoded);
  assert(n1 == n2);

There are also C++-style I/O operators defined for use with
``BigInt``. The input operator understands negative numbers and
hexadecimal numbers (marked with a leading "0x"). The '-' must come
before the "0x" marker. The output operator will never adorn the
output; for example, when printing a hexadecimal number, there will
not be a leading "0x" (though a leading '-' will be printed if the
number is negative). If you want such things, you'll have to do them
yourself.

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

.. cpp:function:: bool is_prime(BigInt n, RandomNumberGenerator& rng, \
                                size_t prob = 56, double is_random = false)

  Test *n* for primality using a probablistic algorithm (Miller-Rabin).  With
  this algorithm, there is some non-zero probability that true will be returned
  even if *n* is actually composite. Modifying *prob* allows you to decrease the
  chance of such a false positive, at the cost of increased runtime. Sufficient
  tests will be run such that the chance *n* is composite is no more than 1 in
  2\ :sup:`prob`. Set *is_random* to true if (and only if) *n* was randomly
  chosen (ie, there is no danger it was chosen maliciously) as far fewer tests
  are needed in that case.

.. cpp:function:: bool quick_check_prime(BigInt n, RandomNumberGenerator& rng)

.. cpp:function:: bool check_prime(BigInt n, RandomNumberGenerator& rng)

.. cpp:function:: bool verify_prime(BigInt n, RandomNumberGenerator& rng)

  Three variations on *is_prime*, with probabilities set to 32, 56, and 80
  respectively.

.. cpp:function:: BigInt random_prime(RandomNumberGenerator& rng, \
                                      size_t bits, \
                                      BigInt coprime = 1, \
                                      size_t equiv = 1, \
                                      size_t equiv_mod = 2)

  Return a random prime number of ``bits`` bits long that is
  relatively prime to ``coprime``, and equivalent to ``equiv`` modulo
  ``equiv_mod``.
