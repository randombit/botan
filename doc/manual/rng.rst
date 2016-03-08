.. _random_number_generators:

Random Number Generators
========================================

The random number generators provided in Botan are meant for creating
keys, IVs, padding, nonces, and anything else that requires 'random'
data. It is important to remember that the output of these classes
will vary, even if they are supplied with the same seed (ie, two
``Randpool`` objects with similar initial states will not produce the
same output, because the value of high resolution timers is added to
the state at various points).

To create a random number generator, instantiate a ``AutoSeeded_RNG``
object. This object will handle choosing the right algorithms from the
set of enabled ones and doing seeding using OS specific
routines. The main service a RandomNumberGenerator provides is, of
course, random numbers:

.. cpp:function:: byte RandomNumberGenerator::next_byte()

  Generates a single random byte and returns it

.. cpp:function:: void RandomNumberGenerator::randomize(byte* data, size_t length)

  Places *length* bytes into the array pointed to by *data*

To ensure good quality output, a PRNG needs to be seeded with truly
random data. Normally this is done for you. However it may happen that
your application has access to data that is potentially unpredictable
to an attacker. If so, use

.. cpp:function:: void RandomNumberGenerator::add_entropy(const byte* data, \
                                                          size_t length)

which incorporates the data into the current randomness state. Don't
worry about filtering the data or doing any kind of cryptographic
preprocessing (such as hashing); the RNG objects in botan are designed
such that you can feed them any arbitrary non-random or even
maliciously chosen data - as long as at some point some of the seed
data was good the output will be secure.


Implementation Notes
----------------------------------------

Randpool
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``Randpool`` is the primary PRNG within Botan. In recent versions all
uses of it have been wrapped by an implementation of the X9.31 PRNG
(see below). If for some reason you should have cause to create a PRNG
instead of using the "global" one owned by the library, it would be
wise to consider the same on the grounds of general caution; while
``Randpool`` is designed with known attacks and PRNG weaknesses in
mind, it is not an standard/official PRNG. The remainder of this
section is a (fairly technical, though high-level) description of the
algorithms used in this PRNG. Unless you have a specific interest in
this subject, the rest of this section might prove somewhat
uninteresting.

``Randpool`` has an internal state called pool, which is 512 bytes
long. This is where entropy is mixed into and extracted from. There is also a
small output buffer (called buffer), which holds the data which has already
been generated but has just not been output yet.

It is based around a MAC and a block cipher (which are currently
HMAC(SHA-256) and AES-256). Where a specific size is mentioned, it
should be taken as a multiple of the cipher's block size. For example,
if a 256-bit block cipher were used instead of AES, all the sizes
internally would double. Every time some new output is needed, we
compute the MAC of a counter and a high resolution timer. The
resulting MAC is XORed into the output buffer (wrapping as needed),
and the output buffer is then encrypted with AES, producing 16 bytes
of output.

After 8 blocks (or 128 bytes) have been produced, we mix the pool. To
do this, we first rekey both the MAC and the cipher; the new MAC key
is the MAC of the current pool under the old MAC key, while the new
cipher key is the MAC of the current pool under the just-chosen MAC
key. We then encrypt the entire pool in CBC mode, using the current
(unused) output buffer as the IV. We then generate a new output
buffer, using the mechanism described in the previous paragraph.

To add randomness to the PRNG, we compute the MAC of the input and XOR
the output into the start of the pool. Then we remix the pool and
produce a new output buffer. The initial MAC operation should make it
very hard for chosen inputs to harm the security of ``Randpool``, and
as HMAC should be able to hold roughly 256 bits of state, it is
unlikely that we are wasting much input entropy (or, if we are, it
doesn't matter, because we have a very abundant supply).

ANSI X9.31
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``ANSI_X931_PRNG`` is the standard issue X9.31 Appendix A.2.4 PRNG,
though using AES-256 instead of 3DES as the block cipher. This PRNG
implementation has been checked against official X9.31 test vectors.

Internally, the PRNG holds a pointer to another PRNG (typically
Randpool). This internal PRNG generates the key and seed used by the
X9.31 algorithm, as well as the date/time vectors. Each time an X9.31
PRNG object receives entropy, it passes it along to the PRNG it is
holding, and then pulls out some random bits to generate a new key and
seed. This PRNG considers itself seeded as soon as the internal PRNG
is seeded.


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
