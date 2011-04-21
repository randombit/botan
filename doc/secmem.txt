
Secure Memory Containers
========================================

A major concern with mixing modern multiuser OSes and cryptographic
code is that at any time the code (including secret keys) could be
swapped to disk, where it can later be read by an attacker. Botan
stores almost everything (and especially anything sensitive) in memory
buffers that a) clear out their contents when their destructors are
called, and b) have easy plugins for various memory locking functions,
such as the ``mlock`` call on many Unix systems.

Two of the allocation method used ("malloc" and "mmap") don't
require any extra privileges on Unix, but locking memory does. At
startup, each allocator type will attempt to allocate a few blocks
(typically totaling 128k), so if you want, you can run your
application ``setuid`` ``root``, and then drop privileges
immediately after creating your ``LibraryInitializer``. If you end
up using more than what's been allocated, some of your sensitive data
might end up being swappable, but that beats running as ``root``
all the time.

These classes should also be used within your own code for storing
sensitive data. They are only meant for primitive data types (int,
long, etc): if you want a container of higher level Botan objects, you
can just use a ``std::vector``, since these objects know how to clear
themselves when they are destroyed. You cannot, however, have a
``std::vector`` (or any other container) of ``Pipe`` objects or
filters, because these types have pointers to other filters, and
implementing copy constructors for these types would be both hard and
quite expensive (vectors of pointers to such objects is fine, though).

These types are not described in any great detail: for more information,
consult the definitive sources~--~the header files ``secmem.h`` and
``allocate.h``.

``SecureBuffer`` is a simple array type, whose size is specified at
compile time. It will automatically convert to a pointer of the
appropriate type, and has a number of useful functions, including
``clear()``, and ``size_t`` ``size()``, which returns the length of
the array. It is a template that takes as parameters a type, and a
constant integer which is how long the array is (for example:
``SecureBuffer<byte, 8> key;``).

``SecureVector`` is a variable length array. Its size can be increased
or decreased as need be, and it has a wide variety of functions useful
for copying data into its buffer. Like ``SecureBuffer``, it implements
``clear`` and ``size``.

Allocators
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The containers described above get their memory from allocators. As a
user of the library, you can add new allocator methods at run time for
containers, including the ones used internally by the library, to
use. The interface to this is in ``allocate.h``. Code needing to
allocate or deallocate memory calls ``get_allocator``, which returns a
pointer to an allocator object. This pointer should not be freed: the
caller does not own the allocator (it is shared among multiple
allocatore users, and uses a mutex to serialize access internally if
necessary). It is possible to call ``get_allocator`` with a specific
name to request a particular type of allocator, otherwise, a default
allocator type is returned.

At start time, the only allocator known is a ``Default_Allocator``,
which just allocates memory using ``malloc``, and zeroizes it when the
memory is released. It is known by the name "malloc". If you ask for
another type of allocator ("locking" and "mmap" are currently used),
and it is not available, some other allocator will be returned.

You can add in a new allocator type using ``add_allocator_type``. This
function takes a string and a pointer to an allocator. The string gives this
allocator type a name to which it can be referred when one is requesting it
with ``get_allocator``. If an error occurs (such as the name being
already registered), this function returns false. It will return true if the
allocator was successfully registered. If you ask it to,
``LibraryInitializer`` will do this for you.

Finally, you can set the default allocator type that will be returned
using the policy setting "default_alloc" to the name of any previously
registered allocator.
