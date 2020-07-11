.. _random_number_generators:

Random Number Generators
========================================

.. cpp:class:: RandomNumberGenerator

   The base class for all RNG objects, is declared in ``rng.h``.

   .. cpp:function:: void randomize(uint8_t* output_array, size_t length)

      Places *length* random bytes into the provided buffer.

   .. cpp:function:: void randomize_with_input(uint8_t* data, size_t length, \
                     const uint8_t* extra_input, size_t extra_input_len)

      Like randomize, but first incorporates the additional input field into the
      state of the RNG. The additional input could be anything which
      parameterizes this request. Not all RNG types accept additional inputs,
      the value will be silently ignored when not supported.

   .. cpp:function:: void randomize_with_ts_input(uint8_t* data, size_t length)

      Creates a buffer with some timestamp values and calls ``randomize_with_input``

      .. note::

         When RDRAND is enabled and available at runtime, instead of timestamps
         the output of RDRAND is used as the additional data.

   .. cpp:function:: uint8_t next_byte()

      Generates a single random byte and returns it. Note that calling this
      function several times is much slower than calling ``randomize`` once to
      produce multiple bytes at a time.

   .. cpp:function:: void add_entropy(const uint8_t* data, size_t length)

      Incorporates provided data into the state of the PRNG, if at all possible.
      This works for most RNG types, including the system and TPM RNGs. But if
      the RNG doesn't support this operation, the data is dropped, no error is
      indicated.

   .. cpp:function:: bool accepts_input() const

      This function returns ``false`` if it is known that this RNG object cannot
      accept external inputs. In this case, any calls to
      :cpp:func:`RandomNumberGenerator::add_entropy` will be ignored.

   .. cpp:function:: void reseed_from_rng(RandomNumberGenerator& rng, \
                     size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS)

      Reseed by calling ``rng`` to acquire ``poll_bits`` data.


RNG Types
----------------------------------------

Several different RNG types are implemented. Some access hardware RNGs, which
are only available on certain platforms. Others are mostly useful in specific
situations.

Generally prefer using either the system RNG, or else ``AutoSeeded_RNG`` which is
intended to provide best possible behavior in a userspace PRNG.

System_RNG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On systems which support it, in ``system_rng.h`` you can access a shared
reference to a process global instance of the system PRNG (using interfaces such
as ``/dev/urandom``, ``getrandom``, ``arc4random``, or ``RtlGenRandom``):

.. cpp:function:: RandomNumberGenerator& system_rng()

   Returns a reference to the system RNG

There is also a wrapper class ``System_RNG`` which simply invokes on
the return value of ``system_rng()``. This is useful in situations where
you may sometimes want to use the system RNG and a userspace RNG in others,
for example::

  std::unique_ptr<Botan::RandomNumberGenerator> rng;
  #if defined(BOTAN_HAS_SYSTEM_RNG)
  rng.reset(new System_RNG);
  #else
  rng.reset(new AutoSeeded_RNG);
  #endif

Unlike nearly any other object in Botan it is acceptable to share a single
instance of ``System_RNG`` between threads, because the underlying RNG is itself
thread safe due to being serialized by a mutex in the kernel itself.

AutoSeeded_RNG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

AutoSeeded_RNG is type naming a 'best available' userspace PRNG. The
exact definition of this has changed over time and may change in the
future, fortunately there is no compatibility concerns when changing
any RNG since the only expectation is it produces bits
indistinguishable from random.

.. note:: Like most other classes in Botan, it is not safe to share an instance
          of ``AutoSeeded_RNG`` among multiple threads without serialization.

The current version uses HMAC_DRBG with either SHA-384 or SHA-256. The
initial seed is generated either by the system PRNG (if available) or
a default set of entropy sources. These are also used for periodic
reseeding of the RNG state.

HMAC_DRBG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HMAC DRBG is a random number generator designed by NIST and specified
in SP 800-90A. It seems to be the most conservative generator of the
NIST approved options.

It can be instantiated with any HMAC but is typically used with
SHA-256, SHA-384, or SHA-512, as these are the hash functions approved
for this use by NIST.

HMAC_DRBG's constructors are:

.. cpp:class:: HMAC_DRBG

      .. cpp:function:: HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf, \
                        RandomNumberGenerator& underlying_rng, \
                        size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL, \
                        size_t max_number_of_bytes_per_request = 64 * 1024)

         Creates a DRBG which will automatically reseed as required by making
         calls to ``underlying_rng`` either after being invoked
         ``reseed_interval`` times, or if use of ``fork`` system call is
         detected.

         You can disable automatic reseeding by setting ``reseed_interval`` to
         zero, in which case ``underlying_rng`` will only be invoked in the case
         of ``fork``.

         The specification of HMAC DRBG requires that each invocation produce no
         more than 64 kibibytes of data. However, the RNG interface allows
         producing arbitrary amounts of data in a single request. To accommodate
         this, ``HMAC_DRBG`` treats requests for more data as if they were
         multiple requests each of (at most) the maximum size. You can specify a
         smaller maximum size with ``max_number_of_bytes_per_request``. There is
         normally no reason to do this.

      .. cpp:function:: HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf, \
                        Entropy_Sources& entropy_sources, \
                        size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL, \
                        size_t max_number_of_bytes_per_request = 64 * 1024)

         Like above function, but instead of an RNG taking a set of entropy
         sources to seed from as required.

      .. cpp:function:: HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf, \
                        RandomNumberGenerator& underlying_rng, \
                        Entropy_Sources& entropy_sources, \
                        size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL, \
                        size_t max_number_of_bytes_per_request = 64 * 1024)

         Like above function, but taking both an RNG and a set of entropy
         sources to seed from as required.

      .. cpp:function:: HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf)

         Creates an unseeded DRBG. You must explicitly provide seed data later
         on in order to use this RNG. This is primarily useful for deterministic
         key generation.

         Since no source of data is available to automatically reseed, automatic
         reseeding is disabled when this constructor is used. If the RNG object
         detects that ``fork`` system call was used without it being
         subsequently reseeded, it will throw an exception.

      .. cpp:function:: HMAC_DRBG(const std::string& hmac_hash)

         Like the constructor just taking a PRF, except instead of a PRF object,
         a string specifying what hash to use with HMAC is provided.

ChaCha_RNG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a very fast userspace PRNG based on ChaCha20 and HMAC(SHA-256). The key
for ChaCha is derived by hashing entropy inputs with HMAC. Then the ChaCha
keystream generator is run, first to generate the new HMAC key (used for any
future entropy additions), then the desired RNG outputs.

This RNG composes two primitives thought to be secure (ChaCha and HMAC) in a
simple and well studied way (the extract-then-expand paradigm), but is still an
ad-hoc and non-standard construction. It is included because it is roughly 20x
faster then HMAC_DRBG (basically running as fast as ChaCha can generate
keystream bits), and certain applications need access to a very fast RNG.

One thing applications using ``ChaCha_RNG`` need to be aware of is that for
performance reasons, no backtracking resistance is implemented in the RNG
design. An attacker who recovers the ``ChaCha_RNG`` state can recover the output
backwards in time to the last rekey and forwards to the next rekey.

An explicit reseeding (:cpp:func:`RandomNumberGenerator::add_entropy`) or
providing any input to the RNG
(:cpp:func:`RandomNumberGenerator::randomize_with_ts_input`,
:cpp:func:`RandomNumberGenerator::randomize_with_input`) is sufficient to cause
a reseeding. Or, if a RNG or entropy source was provided to the ``ChaCha_RNG``
constructor, then reseeding will be performed automatically after a certain
interval of requests.

Processor_RNG
^^^^^^^^^^^^^^^^^

This RNG type directly invokes a CPU instruction capable of generating
a cryptographically secure random number. On x86 it uses ``rdrand``,
on POWER ``darn``. If the relevant instruction is not available, the
constructor of the class will throw at runtime. You can test
beforehand by checking the result of ``Processor_RNG::available()``.

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

The following entropy sources are currently used:

 * The system RNG (``arc4random``, ``/dev/urandom``, or ``RtlGenRandom``).
 * RDRAND and RDSEED are used if available, but not counted as contributing entropy
 * ``/dev/random`` and ``/dev/urandom``. This may be redundant with the system RNG
 * ``getentropy``, only used on OpenBSD currently
 * ``/proc`` walk: read files in ``/proc``. Last ditch protection against
   flawed system RNG.
 * Win32 stats: takes snapshot of current system processes. Last ditch
   protection against flawed system RNG.

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

Therefore, it is strongly recommended to explicitly reseed any
userspace random generators after forking a new process. If this is
not possible in your application, prefer using the system PRNG
instead.
