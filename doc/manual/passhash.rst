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
authentication request, the authenticator can recompute the one way
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
reduce the effectivness of offline dictionary generation, because for
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

Botan provides two techniques for password hashing, bcrypt and
passhash9.

.. _bcrypt:

Bcrypt Password Hashing
----------------------------------------

:wikipedia:`Bcrypt` is a password hashing scheme originally designed
for use in OpenBSD, but numerous other implementations exist.
It is made available by including ``bcrypt.h``.

It has the advantage that it requires a small amount (4K) of fast RAM
to compute, which can make hardware password cracking somewhat more
expensive.

Bcrypt provides outputs that look like this::

  "$2a$12$7KIYdyv8Bp32WAvc.7YvI.wvRlyVn0HP/EhPmmOyMQA4YKxINO0p2"

.. cpp:function:: std::string generate_bcrypt(const std::string& password, \
   RandomNumberGenerator& rng, u16bit work_factor = 10)

   Takes the password to hash, a rng, and a work factor. Higher values
   increase the amount of time the algorithm runs, increasing the cost
   of cracking attempts. The resulting hash is returned as a string.

.. cpp:function:: bool check_bcrypt(const std::string& password, \
   const std::string& hash)

   Takes a password and a bcrypt output and returns true if the
   password is the same as the one that was used to generate the
   bcrypt hash.

.. _passhash9:

Passhash9
----------------------------------------

Botan also provides a password hashing technique called passhash9, in
``passhash9.h``, which is based on PBKDF2. Its outputs look like::

  "$9$AAAKxwMGNPSdPkOKJS07Xutm3+1Cr3ytmbnkjO6LjHzCMcMQXvcT"

This function should be secure with the proper parameters, and will remain in
the library for the forseeable future, but it is specific to Botan rather than
being a widely used password hash. Prefer bcrypt.

.. cpp:function:: std::string generate_passhash9(const std::string& password, \
   RandomNumberGenerator& rng, u16bit work_factor = 10, byte alg_id = 1)

   Functions much like ``generate_bcrypt``. The last parameter,
   ``alg_id``, specifies which PRF to use. Currently defined values are
   0: HMAC(SHA-1), 1: HMAC(SHA-256), 2: CMAC(Blowfish), 3: HMAC(SHA-384), 4: HMAC(SHA-512)

   Currently, this performs 10000 * ``work_factor`` PBKDF2 iterations,
   using 96 bits of salt taken from ``rng``. The iteration count is
   encoded as a 16-bit integer and is multiplied by 10000.

.. cpp:function:: bool check_passhash9(const std::string& password, \
   const std::string& hash)

   Functions much like ``check_bcrypt``
