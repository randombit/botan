.. _random_number_generators:

Random Number Generators
========================================

The base class ``RandomNumberGenerator`` is in the header ``botan/rng.h``.

The major interfaces are

.. cpp:function:: void RandomNumberGenerator::randomize(byte* output_array, size_t length)

  Places *length* random bytes into the provided buffer.

.. cpp:function:: void RandomNumberGenerator::add_entropy(const byte* data, size_t length)

  Incorporates provided data into the state of the PRNG, if at all
  possible.  This works for most RNG types, including the system and
  TPM RNGs. But if the RNG doesn't support this operation, the data is
  dropped, no error is indicated.

.. cpp:function:: void RandomNumberGenerator::randomize_with_input(byte* data, size_t length, \
    const byte* ad, size_t ad_len)

  Like randomize, but first incorporates the additional input field
  into the state of the RNG. The additional input could be anything which
  parameterizes this request.

.. cpp:function:: void RandomNumberGenerator::randomize_with_ts_input(byte* data, size_t length)

  Creates a buffer with some timestamp values and calls ``randomize_with_input``

.. cpp:function:: byte RandomNumberGenerator::next_byte()

  Generates a single random byte and returns it. Note that calling this
  function several times is much slower than calling ``randomize`` once
  to produce multiple bytes at a time.

RNG Types
----------------------------------------

The following RNG types are included

HMAC_DRBG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HMAC DRBG is a random number generator designed by NIST and specified
in SP 800-90A. It seems to be the most conservative generator of the
NIST approved options.

It can be instantiated with any HMAC but is typically used with
SHA-256, SHA-384, or SHA-512, as these are the hash functions approved
for this use by NIST.

System_RNG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In ``system_rng.h``, objects of ``System_RNG`` reference a single
(process global) reference to the system PRNG (such as
``/dev/urandom`` or ``CryptGenRandom``).

You can also use the function ``system_rng()`` which returns a
reference to the global handle to the system RNG.

AutoSeeded_RNG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

AutoSeeded_RNG is type naming a 'best available' userspace PRNG. The
exact definition of this has changed over time and may change in the
future, fortunately there is no compatability concerns when changing
such an RNG.

Note well: like most other classes in Botan, it is not safe to share
an instance of ``AutoSeeded_RNG`` among multiple threads without
serialization.

The current version uses the HMAC_DRBG with SHA-384 or SHA-256. The
initial seed is generated either by the system PRNG (if available) or
a default set of entropy sources. These are also used for periodic
reseeding of the RNG state.

TPM_RNG
^^^^^^^^^^^^^^^^^

This RNG type allows using the RNG exported from a TPM chip.

PKCS11_RNG
^^^^^^^^^^^^^^^^^

This RNG type allows using the RNG exported from a hardware token accessed via PKCS11.

Entropy Sources
---------------------------------

An ``EntropySource`` is an abstract representation of some method of
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

Fork Safety
---------------------------------

On Unix platforms, the ``fork()`` and ``clone()`` system calls can
be used to spawn a new child process. Fork safety ensures that the
child process doesn't see the same output of random bytes as the
parent process. Botan tries to ensure fork safety by feeding the
process ID into the internal state of the random generator and by
automatically reseeding the random generator if the process ID
changed between two requests of random bytes. However, this does
not protect against PID wrap around. The process ID is usually
implemented as a 16 bit integer. In this scenario, a process will
spawn a new child process, which exits the parent process and
spawns a new child process himself. If the PID wrapped around, the
second child process may get assigned the process ID of it's 
grandparent and the fork safety can not be ensured.

Therefore, it is strongly recommended to explicitly reseed the
random generator after forking a new process.
