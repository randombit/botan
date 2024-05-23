Semantic Versioning
=====================

Starting with 2.0.0, Botan adopted semantic versioning. This means we endevour
to make no change which will either break compilation of existing code, or cause
different behavior in a way that will cause compatability issues. Such changes
are reserved for new major versions.

If on upgrading to a new minor version, you encounter a problem where your
existing code either fails to compile, or the code behaves differently in some
way that causes trouble, it is probably a bug; please report it on Github.

There are important exceptions to the SemVer guarantees that you
should be aware of, described in the following list.

Exception #1: Deriving from Library Classes
--------------------------------------------

If you in your application derive a new class from a class in the
library, we do not guarantee a future minor release will not break
your code. For example, we may in a minor release introduce a new pure
virtual function to a base class like ``BlockCipher``, and implement
it for all subclasses within the library. In this case your code would
fail to compile until you implemented the new virtual function. Or we
might rename or remove a protected function, or a protected member
variable.

There is also an exception to this exception! The following classes are intended
for derivation by applications, and are fully covered by SemVer:

* ``Credentials_Manager``
* ``Entropy_Source``
* ``TLS::Callbacks``
* ``TLS::Policy`` (and subclasses thereof)
* ``TLS::Stream<T>``

Exception #2: ``BOTAN_UNSTABLE_API``
--------------------------------------

Certain functionality is available to users, and marked in the header
using the macro ``BOTAN_UNSTABLE_API``. These interfaces are not
covered by SemVer and may change or even vanish in a minor release.

Usually these interfaces are to enable applications that need to do
something "interesting", but we are not confident that the API is any
good. Examples include interfaces allowing applications to write
custom TLS extensions and custom public key operations.

Exception #3: Experimental modules
--------------------------------------

Certain modules can be marked as experimental in the build system.
Such modules are not built by default. Any functionality exposed by
such modules may change or vanish at any time without warning. See
:ref:`building` for more information on enabling or disabling these
modules.

Exception #4: Any function starting with ``_``
-----------------------------------------------

For various technical reasons, some functions are available for public
use but are really only intended for use by the library itself.

The developers denote such functions by starting them with an underscore
(``_``). Any such function may change or disappear at any time.
