Semantic Versioning
=====================

Starting with 2.0.0, Botan adopted semantic versioning. This means we endevour
to make no change which will either break compilation of existing code, or cause
different behavior in a way that will cause compatability issues. Such changes
are reserved for new major versions.

If on upgrading to a new minor version, you encounter a problem where your
existing code either fails to compile, or the code behaves differently in some
way that causes trouble, it is probably a bug; please report it on Github.

Note that none of these guarantees apply to "experimental modules" that are not
built by default. The functionality as well as API of such modules may change or
even disappear in a minor version without warning. See :ref:`building` for more
information on enabling or disabling these modules.

Exception
-----------------------

There is an important exception to the SemVer guarantees that you should be
aware of. If you in your application derive a new class from a class in the
library, we do not guarantee a future minor release will not break your
code. For example, we may in a minor release introduce a new pure virtual
function to a base class like ``BlockCipher``, and implement it for all
subclasses within the library. In this case your code would fail to compile
until you implemented the new virtual function. Or we might rename or remove a
protected function, or a protected member variable.

There is also an exception to this exception! The following classes are intended
for derivation by applications, and are fully covered by SemVer:

* ``Credentials_Manager``
* ``Entropy_Source``
* ``TLS::Callbacks``
* ``TLS::Policy`` (and subclasses thereof)
* ``TLS::Stream<T>``
