.. _random_number_generators:

Random Number Generators
========================================

``RandomNumberGenerator`` is an interface class defined in ``rng.h``,
with primary functions

``void randomize(byte output[], size_t length)``

The primary interface, writes random data to output[0:length].

``secure_vector<byte> random_vec(size_t bytes)``

A convenience function, returns a vector of the requested length.

``byte next_byte()``

Returns a single random byte

``byte next_nonzero_byte()``

Returns a single random byte between 1 and 255

The library takes a ``RandomNumberGenerator`` reference anywhere
random numbers are required.

System RNG
--------------------------------------

Some systems offer a system RNG (currently /dev/urandom and
CryptGenRandom are supported).

If ``BOTAN_HAS_SYSTEM_RNG`` is defined, then the header
``system_rng.h`` contains

``RandomNumberGenerator& system_rng();``

which returns the global handle to the system RNG.

The header also defines

``class System_RNG : public RandomNumberGenerator``

which is just an instantiatable reference to ``system_rng``

Userspace RNG
-----------------

A userspace RNG works by collecting entropy inputs from different
sources and using them to seed a determinstic generator.

The default userspace RNG in the library is available as `AutoSeeded_RNG`;
it is currently implement using HMAC_DRBG from NIST SP 800-90A.

Current entropy sources in the library include /dev/urandom,
CryptGenRandom, RDRAND, RDSEED, and various methods of gathering
system statistics used on Windows, Linux, and generic Unix systems.

HMAC_DRBG
----------------------------

Occasionally a completely deterministic source of random numbers is
required. For example, this can be used to expand a small symmetric
key (such as the hash of a user's password) into a potentially larger
value (such as an ECDSA or McEliece key). For these purposes HMAC_DRBG
can also be used directly.

HMAC_DRBG accepts an optional parameter which specifies the reseed
rate. If this parameter is zero, automatic reseeds based on the number
of outputs is disabled. SP 800-90A recommends this be finite and no
more than 2**48, the default is ``BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED``
which is a compile-time parameter set in build.h

Adding Entropy/Reseeding
-----------------------------

There is an interface for adding entropy to the RNG state. This is
implemented even for the system RNG, as both /dev/urandom and
CryptGenRandom support adding entropy to the current state.

``add_entropy(const byte input[], size_t length)``

Adds some block of system

``size_t reseed(size_t bits_to_collect = BOTAN_RNG_RESEED_POLL_BITS)``


``size_t reseed_with_timeout(size_t bits_to_collect,
                             std::chrono::milliseconds poll_timeout);``

``size_t reseed_with_sources(Entropy_Sources& srcs,
                             size_t poll_bits,
                             std::chrono::milliseconds poll_timeout);``


Build Configuration of RNG Reseeding
--------------------------------------

There are a number of build options for RNGs set in ``build.h``

- ``BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED`` after a given amount of
  output a userspace RNG will reseed itself from the entropy sources.

- ``BOTAN_RNG_AUTO_RESEED_POLL_BITS`` if the output limit is reached,
   the RNG will attempt to reseed with this many bits of entropy.

- ``BOTAN_RNG_AUTO_RESEED_TIMEOUT`` specifies the maximum amount of
  time a reseed poll should run. If after this amount of time the
  reseed is not complete the poll will return just the entropy
  collected so far.

- ``BOTAN_RNG_RESEED_POLL_BITS`` specifies the default entropy target for
  a RNG which is unseeded or for when a fork is detected.

- ``BOTAN_RNG_RESEED_DEFAULT_TIMEOUT`` specifies the timeout used for
  ``RandomNumberGenerator::reseed``

- ``BOTAN_ENTROPY_DEFAULT_SOURCES`` lists the sources that will be used
  by default for reseeding.


Entropy Sources
---------------------------------

An ``Entropy_Source`` class represents some mechanism for gathering
inputs which 

is an abstract representation of some method of
gather "real" entropy. This tends to be very system dependent. The
*only* way you should use an ``EntropySource`` is to pass it to a PRNG
that will extract entropy from it -- never use the output directly for
any kind of key or nonce generation!

``EntropySource`` has a pair of functions for getting entropy from
some external source, called ``fast_poll`` and ``slow_poll``. These
pass a buffer of bytes to be written; the functions then return how
many bytes of entropy were gathered.

Note for writers of ``EntropySource`` subclasses: it isn't necessary
to use any kind of cryptographic hash on your output. The data
produced by an EntropySource is only used by an application after it
has been hashed by the ``RandomNumberGenerator`` that asked for the
entropy, thus any hashing you do will be wasteful of both CPU cycles
and entropy.
