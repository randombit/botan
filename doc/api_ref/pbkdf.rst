
.. _pbkdf:

Password Based Key Derivation
========================================

Often one needs to convert a human readable password into a cryptographic
key. It is useful to slow down the computation of these computations in order to
reduce the speed of brute force search, thus they are parameterized in some
way which allows their required computation to be tuned.

PBKDF
---------

:cpp:class:`PBKDF` is the older API for this functionality, presented in header
``pbkdf.h``. It does not support Scrypt, nor will it be able to support other
future hashes (such as Argon2) that may be added in the future. In addition,
this API requires the passphrase be entered as a ``std::string``, which means
the secret will be stored in memory that will not be zeroed.

.. cpp:class:: PBKDF

   .. cpp:function:: void pbkdf_iterations(uint8_t out[], size_t out_len, \
                            const std::string& passphrase, \
                            const uint8_t salt[], size_t salt_len, \
                            size_t iterations) const

      Run the PBKDF algorithm for the specified number of iterations,
      with the given salt, and write output to the buffer.

   .. cpp:function:: void pbkdf_timed(uint8_t out[], size_t out_len, \
                         const std::string& passphrase, \
                         const uint8_t salt[], size_t salt_len, \
                         std::chrono::milliseconds msec, \
                         size_t& iterations) const

      Choose (via short run-time benchmark) how many iterations to perform
      in order to run for roughly msec milliseconds. Writes the number
      of iterations used to reference argument.

   .. cpp:function:: OctetString derive_key( \
               size_t output_len, const std::string& passphrase, \
               const uint8_t* salt, size_t salt_len, \
               size_t iterations) const

   Computes a key from *passphrase* and the *salt* (of length
   *salt_len* bytes) using an algorithm-specific interpretation of
   *iterations*, producing a key of length *output_len*.

   Use an iteration count of at least 10000. The salt should be
   randomly chosen by a good random number generator (see
   :ref:`random_number_generators` for how), or at the very least
   unique to this usage of the passphrase.

   If you call this function again with the same parameters, you will
   get the same key.

PasswordHash
--------------

.. versionadded:: 2.8.0

This API has two classes, one representing the algorithm (such as
"PBKDF2(SHA-256)", or "Scrypt") and the other representing a specific instance
of the problem which is fully specified (say "Scrypt" with N=8192,r=64,p=8).

.. cpp:class:: PasswordHash

   .. cpp:function:: void derive_key(uint8_t out[], size_t out_len, \
                     const char* password, const size_t password_len, \
                     const uint8_t salt[], size_t salt_len) const

      Derive a key, placing it into output

   .. cpp:function:: std::string to_string() const

      Return a descriptive string including the parameters (iteration count, etc)

The ``PasswordHashFamily`` creates specific instances of ``PasswordHash``:

.. cpp:class:: PasswordHashFamily

   .. cpp:function:: static std::unique_ptr<PasswordHashFamily> create(const std::string& what)

      For example "PBKDF2(SHA-256)", "Scrypt", "OpenPGP-S2K(SHA-384)". Returns
      null if not available.

   .. cpp:function:: std::unique_ptr<PasswordHash> default_params() const

      Create a default instance of the password hashing algorithm. Be warned the
      value returned here may change from release to release.

   .. cpp:function:: std::unique_ptr<PasswordHash> tune(size_t output_len, std::chrono::milliseconds msec) const

      Return a password hash instance tuned to run for approximately ``msec``
      milliseconds when producing an output of length ``output_len``. (Accuracy
      may vary, use the command line utility ``botan pbkdf_tune`` to check.)

   .. cpp:function:: std::unique_ptr<PasswordHash> from_params( \
         size_t i1, size_t i2 = 0, size_t i3 = 0) const

      Create a password hash using some scheme specific format. Parameters are as follows:
      - For PBKDF2, PGP-S2K, and Bcrypt-PBKDF, i1 is iterations
      - Scrypt uses N, r, p for i{1-3}
      - Argon2 family uses memory (in KB), iterations, and parallelism for i{1-3}
      All unneeded parameters should be set to 0 or left blank.

Available Schemes
----------------------

General Recommendations
^^^^^^^^^^^^^^^^^^^^^^^^^

If you need wide interoperability use PBKDF2 with HMAC-SHA256 and at least 10K
iterations. If you don't, use Scrypt with N=32768, r=8, p=1.

You can test how long a particular PBKDF takes to execute using the cli tool
``pbkdf_tune``::

  $ ./botan pbkdf_tune --algo=Argon2id 500 --max-mem=192 --check
  For 500 ms selected Argon2id(196608,3,1) using 192 MiB took 413.159 msec to compute

This indicates the parameters chosen by the fast auto-tuning algorithm and
because ``--check`` was supplied the hash is also executed with the full set of
parameters and timed.


PBKDF2
^^^^^^^^^^^^

PBKDF2 is the "standard" password derivation scheme, widely implemented in many
different libraries. It uses HMAC internally and requires choosing a hash
function to use. (If in doubt use SHA-256 or SHA-512). It also requires choosing
an iteration count, which makes brute force attacks more expensive. Use *at
least* 10000 and preferably much more.

Scrypt
^^^^^^^^^^

Scrypt is a relatively newer design which is "memory hard" - in
addition to requiring large amounts of CPU power it uses a large block
of memory to compute the hash. This makes brute force attacks using
ASICs substantially more expensive.

Scrypt is not supported through :cpp:class:`PBKDF`, only :cpp:class:`PasswordHash`,
starting in 2.8.0. In addition, starting in version 2.7.0, scrypt is available
with this function:

.. cpp:function:: void scrypt(uint8_t output[], size_t output_len, \
                              const std::string& password, \
                              const uint8_t salt[], size_t salt_len, \
                              size_t N, size_t r, size_t p)

   Computes the Scrypt using the password and salt, and produces an output
   of arbitrary length.

   The N, r, p parameters control how much work and memory Scrypt
   uses.  N is the primary control of the workfactor, and must be a
   power of 2. For interactive logins use 32768, for protection of
   secret keys or backups use 1048576.

   The r parameter controls how 'wide' the internal hashing operation
   is. It also increases the amount of memory that is used. Values
   from 1 to 8 are reasonable.

   Setting p parameter to greater than one splits up the work in a way
   that up to p processors can work in parallel.

   As a general recommendation, use N=32768, r=8, p=1

Argon2
^^^^^^^^^^

.. versionadded:: 2.11.0

Argon2 is the winner of the PHC (Password Hashing Competition) and
provides a tunable memory hard PBKDF. There are three minor variants
of Argon2 - Argon2d, Argon2i, and Argon2id. All three are implemented.

Bcrypt
^^^^^^^^^^^^

.. versionadded:: 2.11.0

Bcrypt-PBKDF is a variant of the well known ``bcrypt`` password hashing
function.  Like ``bcrypt`` it is based around using Blowfish for the key
expansion, which requires 4 KiB of fast random access memory, making hardware
based attacks more expensive. Unlike Argon2 or Scrypt, the memory usage is not
tunable.

This function is relatively obscure but is used for example in OpenSSH.
Prefer Argon2 or Scrypt in new systems.

OpenPGP S2K
^^^^^^^^^^^^

.. warning::

   The OpenPGP algorithm is weak and strange, and should be avoided unless
   implementing OpenPGP.

There are some oddities about OpenPGP's S2K algorithms that are documented
here. For one thing, it uses the iteration count in a strange manner; instead of
specifying how many times to iterate the hash, it tells how many *bytes* should
be hashed in total (including the salt). So the exact iteration count will
depend on the size of the salt (which is fixed at 8 bytes by the OpenPGP
standard, though the implementation will allow any salt size) and the size of
the passphrase.

To get what OpenPGP calls "Simple S2K", set iterations to 0, and do not specify
a salt. To get "Salted S2K", again leave the iteration count at 0, but give an
8-byte salt. "Salted and Iterated S2K" requires an 8-byte salt and some
iteration count (this should be significantly larger than the size of the
longest passphrase that might reasonably be used; somewhere from 1024 to 65536
would probably be about right). Using both a reasonably sized salt and a large
iteration count is highly recommended to prevent password guessing attempts.
