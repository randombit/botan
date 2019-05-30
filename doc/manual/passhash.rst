Password Hashing
========================================

Storing passwords for user authentication purposes in plaintext is the
simplest but least secure method; when an attacker compromises the
database in which the passwords are stored, they immediately gain
access to all of them. Often passwords are reused among multiple
services or machines, meaning once a password to a single service is
known an attacker has a substantial head start on attacking other
machines.

The general approach is to store, instead of the password, the output
of a one way function of the password. Upon receiving an
authentication request, the authenticating party can recompute the one way
function and compare the value just computed with the one that was
stored. If they match, then the authentication request succeeds. But
when an attacker gains access to the database, they only have the
output of the one way function, not the original password.

Common hash functions such as SHA-256 are one way, but used alone they
have problems for this purpose. What an attacker can do, upon gaining
access to such a stored password database, is hash common dictionary
words and other possible passwords, storing them in a list. Then he
can search through his list; if a stored hash and an entry in his list
match, then he has found the password. Even worse, this can happen
*offline*: an attacker can begin hashing common passwords days,
months, or years before ever gaining access to the database. In
addition, if two users choose the same password, the one way function
output will be the same for both of them, which will be visible upon
inspection of the database.

There are two solutions to these problems: salting and
iteration. Salting refers to including, along with the password, a
randomly chosen value which perturbs the one way function. Salting can
reduce the effectiveness of offline dictionary generation, because for
each potential password, an attacker would have to compute the one way
function output for all possible salts. It also prevents the same
password from producing the same output, as long as the salts do not
collide. Choosing n-bit salts randomly, salt collisions become likely
only after about 2\ :sup:\ `(n/2)` salts have been generated. Choosing a
large salt (say 80 to 128 bits) ensures this is very unlikely. Note
that in password hashing salt collisions are unfortunate, but not
fatal - it simply allows the attacker to attack those two passwords in
parallel easier than they would otherwise be able to.

The other approach, iteration, refers to the general technique of
forcing multiple one way function evaluations when computing the
output, to slow down the operation. For instance if hashing a single
password requires running SHA-256 100,000 times instead of just once,
that will slow down user authentication by a factor of 100,000, but
user authentication happens quite rarely, and usually there are more
expensive operations that need to occur anyway (network and database
I/O, etc). On the other hand, an attacker who is attempting to break a
database full of stolen password hashes will be seriously
inconvenienced by a factor of 100,000 slowdown; they will be able to
only test at a rate of .0001% of what they would without iterations
(or, equivalently, will require 100,000 times as many zombie botnet
hosts).

Memory usage while checking a password is also a consideration; if the
computation requires using a certain minimum amount of memory, then an
attacker can become memory-bound, which may in particular make
customized cracking hardware more expensive. Some password hashing
designs, such as scrypt, explicitly attempt to provide this. The
bcrypt approach requires over 4 KiB of RAM (for the Blowfish key
schedule) and may also make some hardware attacks more expensive.

Botan provides three techniques for password hashing: Argon2, bcrypt, and
passhash9 (based on PBKDF2).

Argon2
----------------------------------------

.. versionadded:: 2.11.0

Argon2 is the winner of the PHC (Password Hashing Competition) and provides
a tunable memory hard password hash. It has a standard string encoding, which looks like::

  "$argon2i$v=19$m=8192,t=10,p=3$YWFhYWFhYWE$itkWB9ODqTd85wUsoib7pfpVTNGMOu0ZJan1odl25V8"

Argon2 has three tunable parameters: ``M``, ``p``, and ``t``. ``M`` gives the
total memory consumption of the algorithm in kilobytes. Increasing ``p``
increases the available parallelism of the computation. The ``t`` parameter
gives the number of passes which are made over the data.

.. note::
   Currently Botan does not make use of ``p`` > 1, so it is best to set it to 1
   to minimize any advantage to highly parallel cracking attempts.

There are three variants of Argon2, namely Argon2d, Argon2i and Argon2id.
Argon2d uses data dependent table lookups with may leak information about the
password via side channel attacks, and is **not recommended** for password
hashing. Argon2i uses data independent table lookups and is immune to these
attacks, but at the cost of requiring higher ``t`` for security. Argon2id uses a
hybrid approach which is thought to be highly secure. The algorithm designers
recommend using Argon2id with ``t`` and ``p`` both equal to 1 and ``M`` set to
the largest amount of memory usable in your environment.

.. cpp:function:: std::string argon2_generate_pwhash(const char* password, size_t password_len, \
                          RandomNumberGenerator& rng, \
                          size_t p, size_t M, size_t t, \
                          size_t y = 2, size_t salt_len = 16, size_t output_len = 32)

   Generate an Argon2 hash of the specified password. The ``y`` parameter specifies
   the variant: 0 for Argon2d, 1 for Argon2i, and 2 for Argon2id.

.. cpp:function:: bool argon2_check_pwhash(const char* password, size_t password_len, \
                                           const std::string& hash)

   Verify an Argon2 password hash against the provided password. Returns false if
   the input hash seems malformed or if the computed hash does not match.

Bcrypt
----------------------------------------

`Bcrypt <https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf>`_ is a
password hashing scheme originally designed for use in OpenBSD, but numerous
other implementations exist. It is made available by including ``bcrypt.h``.

It has the advantage that it requires a small amount (4K) of fast RAM
to compute, which can make hardware password cracking somewhat more
expensive.

Bcrypt provides outputs that look like this::

  "$2a$12$7KIYdyv8Bp32WAvc.7YvI.wvRlyVn0HP/EhPmmOyMQA4YKxINO0p2"

.. note::

   Due to the design of bcrypt, the password is effectively truncated at 72
   characters; further characters are ignored and do not change the hash. To
   support longer passwords, one common approach is to pre-hash the password
   with SHA-256, then run bcrypt using the hex or base64 encoding of the hash as
   the password. (Many bcrypt implementations truncate the password at the first
   NULL character, so hashing the raw binary SHA-256 may cause problems. Botan's
   bcrypt implementation will hash whatever values are given in the
   ``std::string`` including any embedded NULLs so this is not an issue, but
   might cause interop problems if another library needs to validate the
   password hashes.)

.. cpp:function:: std::string generate_bcrypt(const std::string& password, \
                    RandomNumberGenerator& rng, \
                    uint16_t work_factor = 12, \
                    char bcrypt_version = "a")

   Takes the password to hash, a rng, and a work factor.
   The resulting password hash is returned as a string.

   Higher work factors increase the amount of time the algorithm runs,
   increasing the cost of cracking attempts. The increase is exponential, so a
   work factor of 12 takes roughly twice as long as work factor 11. The default
   work factor was set to 10 up until the 2.8.0 release.

   It is recommended to set the work factor as high as your system can tolerate
   (from a performance and latency perspective) since higher work factors greatly
   improve the security against GPU-based attacks.  For example, for protecting
   high value administrator passwords, consider using work factor 15 or 16; at
   these work factors each bcrypt computation takes several seconds. Since admin
   logins will be relatively uncommon, it might be acceptable for each login
   attempt to take some time. As of 2018, a good password cracking rig (with 8
   NVIDIA 1080 cards) can attempt about 1 billion bcrypt computations per month
   for work factor 13. For work factor 12, it can do twice as many.  For work
   factor 15, it can do only one quarter as many attempts.

   Due to bugs affecting various implementations of bcrypt, several different
   variants of the algorithm are defined. As of 2.7.0 Botan supports generating
   (or checking) the 2a, 2b, and 2y variants.  Since Botan has never been
   affected by any of the bugs which necessitated these version upgrades, all
   three versions are identical beyond the version identifier. Which variant to
   use is controlled by the ``bcrypt_version`` argument.

   The bcrypt work factor must be at least 4 (though at this work factor bcrypt
   is not very secure). The bcrypt format allows up to 31, but Botan currently
   rejects all work factors greater than 18 since even that work factor requires
   roughly 15 seconds of computation on a fast machine.

.. cpp:function:: bool check_bcrypt(const std::string& password, \
   const std::string& hash)

   Takes a password and a bcrypt output and returns true if the
   password is the same as the one that was used to generate the
   bcrypt hash.

.. _passhash9:

Passhash9
----------------------------------------

Botan also provides a password hashing technique called passhash9, in
``passhash9.h``, which is based on PBKDF2.

Passhash9 hashes look like::

  "$9$AAAKxwMGNPSdPkOKJS07Xutm3+1Cr3ytmbnkjO6LjHzCMcMQXvcT"

This function should be secure with the proper parameters, and will remain in
the library for the foreseeable future, but it is specific to Botan rather than
being a widely used password hash. Prefer bcrypt or Argon2.

.. warning::

   This password format string ("$9$") conflicts with the format used
   for scrypt password hashes on Cisco systems.

.. cpp:function:: std::string generate_passhash9(const std::string& password, \
   RandomNumberGenerator& rng, uint16_t work_factor = 15, uint8_t alg_id = 4)

   Functions much like ``generate_bcrypt``. The last parameter,
   ``alg_id``, specifies which PRF to use. Currently defined values are
   0: HMAC(SHA-1), 1: HMAC(SHA-256), 2: CMAC(Blowfish), 3: HMAC(SHA-384), 4: HMAC(SHA-512)

   The work factor must be greater than zero and less than 512. This performs
   10000 * ``work_factor`` PBKDF2 iterations, using 96 bits of salt taken from
   ``rng``. Using work factor of 10 or more is recommended.

.. cpp:function:: bool check_passhash9(const std::string& password, \
   const std::string& hash)

   Functions much like ``check_bcrypt``
