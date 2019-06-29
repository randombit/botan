
Mistakes Were Made
===================

These are mistakes made early on in the project's history which are difficult to
fix now, but mentioned in the hope they may serve as an example for others.

C++ API
---------

As an implementation language, I still think C++ is the best choice (or at least
the best choice available in early '00s) at offering good performance,
reasonable abstractions, and low overhead. But the user API should have been
pure C with opaque structs (rather like the FFI layer, which was added much
later). Then an expressive C++ API could be built on top of the C API. This
would have given us a stable ABI, allowed C applications to use the library, and
(these days) make it easier to progressively rewrite the library in Rust.

Public Algorithm Specific Classes
------------------------------------

Classes like AES_128 and SHA_256 should never have been exposed to applications.
Intead such operations should have been accessible only via the higher level
interfaces (here BlockCipher and HashFunction). This would substantially reduce
the overall API and ABI surface.

These interfaces are now deprecated, and perhaps will be able to be
removed eventually.

Header Directories
-------------------

It would have been better to install all headers as ``X/header.h``
where ``X`` is the base dir in the source, eg ``block/aes128.h``,
``hash/md5.h``, ...

Exceptions
-----------

Constant ABI headaches from this, and it impacts performance and makes APIs
harder to understand. Should have been handled with a result<> type instead.

Virtual inheritance
---------------------

This was used in the public key interfaces and the hierarchy is a tangle.
Public and private keys should be distinct classes, with a function on private
keys that creates a new object corresponding to the public key.

Cipher Interface
------------------

The cipher interface taking a secure_vector that it reads from and writes to was
an artifact of an earlier design which supported both compression and encryption
in a single API. But it leads to inefficient copies.

(I am hoping this issue can be somewhat fixed by introducing a new cipher API
and implementing the old API in terms of the new one.)

Pipe Interface
----------------

On the surface this API seems very convenient and easy to use. And it is.  But
the downside is it makes the application code totally opaque; some bytes go into
a Pipe object and then come out the end transformed in some way. What happens in
between? Unless the Pipe was built in the same function and you can see the
parameters to the constructor, there is no way to find out.

The problems with the Pipe API are documented, and it is no longer used within
the library itself. But since many people seem to like it and many applications
use it, we are stuck at least with maintaining it as it currently exists.

License
---------

MIT is more widely used and doesn't have the ambiguity surrounding the
various flavors of BSD.
