BigInt
========================================

``BigInt`` is Botan's implementation of a multiple-precision integer. Thanks to
C++'s operator overloading features, using ``BigInt`` is often quite similar to
using a native integer type. The number of functions related to ``BigInt`` is
quite large, and not all of them are documented here. You can find the complete
declarations in ``botan/bigint.h`` and ``botan/numthry.h`` or the Doxygen
documentation.

.. doxygenclass:: Botan::BigInt
   :members: BigInt,bytes,bits,is_even,is_odd,set_bit,clear_bit,get_bit,binary_encode,encode,encode_locked,encode_1363,decode,to_hex_string,to_dec_string

Number Theory
----------------------------------------

Number theoretic functions available include:

.. doxygenfunction:: Botan::gcd

.. doxygenfunction:: Botan::lcm

.. doxygenfunction:: Botan::jacobi

.. doxygenfunction:: Botan::inverse_mod

.. doxygenfunction:: Botan::power_mod

.. doxygenfunction:: Botan::sqrt_modulo_prime

.. doxygenfunction:: Botan::is_prime

.. doxygenfunction:: Botan::random_prime
