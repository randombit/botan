
.. _pbkdf:

Password Based Key Derivation
========================================

Often one needs to convert a human readable password into a cryptographic
key. It is useful to slow down the computation of these computations in order to
reduce the speed of brute force search, thus they are parameterized in some
way which allows their required computation to be tuned.

PasswordHash
--------------

.. versionadded:: 2.8.0

This API, declared in ``pwdhash.h``, has two classes, ``PasswordHashFamily``
representing the general algorithm, such as "PBKDF2(SHA-256)", or "Scrypt", and
``PasswordHash`` representing a specific instance of the problem which is fully
specified with all parameters (say "Scrypt" with ``N`` = 8192, ``r`` = 64, and
``p`` = 8) and which can be used to derive keys.

API Overview
^^^^^^^^^^^^

.. container:: toggle

   .. doxygenclass:: Botan::PasswordHash
      :members:

PasswordHashFamily
------------------

The ``PasswordHashFamily`` creates specific instances of ``PasswordHash`` by
tuning the algoritm's parameters to the application's needs.

API Overview
^^^^^^^^^^^^

.. container:: toggle

   .. doxygenclass:: Botan::PasswordHashFamily
      :members: create,create_or_throw,default_params,tune,from_iterations,from_params

Code Example
------------

An example demonstrating using the API to hash a password using Argon2i:

.. literalinclude:: /../src/examples/pwdhash.cpp
   :language: cpp

Available Schemes
----------------------

General Recommendations
^^^^^^^^^^^^^^^^^^^^^^^^^

If you need wide interoperability use PBKDF2 with HMAC-SHA256 and at least 50K
iterations. If you don't, use Argon2id with p=1, t=3 and M as large as you
can reasonably set (say 1 gigabyte).

You can test how long a particular PBKDF takes to execute using the cli tool
``pbkdf_tune``::

  $ ./botan pbkdf_tune --algo=Argon2id 500 --max-mem=192 --check
  For 500 ms selected Argon2id(196608,3,1) using 192 MiB took 413.159 msec to compute

This returns the parameters chosen by the fast auto-tuning algorithm, and
because ``--check`` was supplied the hash is also executed with the full set of
parameters and timed.

PBKDF2
^^^^^^^^^^^^

PBKDF2 is the "standard" password derivation scheme, widely implemented in many
different libraries. It uses HMAC internally and requires choosing a hash
function to use. (If in doubt use SHA-256 or SHA-512). It also requires choosing
an iteration count, which makes brute force attacks more expensive. Use *at
least* 50000 and preferably much more. Using 250,000 would not be unreasonable.

Scrypt
^^^^^^^^^^

.. versionadded:: 2.7.0

Scrypt is a relatively newer design which is "memory hard" - in
addition to requiring large amounts of CPU power it uses a large block
of memory to compute the hash. This makes brute force attacks using
ASICs substantially more expensive.

Scrypt has three parameters, usually termed ``N``, ``r``, and ``p``.  ``N`` is
the primary control of the workfactor, and must be a power of 2. For interactive
logins use 32768, for protection of secret keys or backups use 1048576.

The ``r`` parameter controls how 'wide' the internal hashing operation is. It
also increases the amount of memory that is used. Values from 1 to 8 are
reasonable.

Setting ``p`` parameter to greater than 1 splits up the work in a way that up
to p processors can work in parallel.

As a general recommendation, use ``N`` = 32768, ``r`` = 8, ``p`` = 1

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

PBKDF
---------

:cpp:class:`PBKDF` is the older API for this functionality, presented in header
``pbkdf.h``. It only supports PBKDF2 and the PGP S2K algorithm, not
Scrypt, Argon2, or bcrypt. This interface is deprecated and will be removed
in a future major release.

In addition, this API requires the passphrase be entered as a
``std::string``, which means the secret will be stored in memory that
will not be zeroed.

API Overview
^^^^^^^^^^^^

.. container:: toggle

   .. doxygenclass:: Botan::PBKDF
      :members: pbkdf,pbkdf_iterations,pbkdf_timed,derive_key
