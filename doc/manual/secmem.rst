
Memory container
========================================

A major concern with mixing modern multi-user OSes and cryptographic
code is that at any time the code (including secret keys) could be
swapped to disk, where it can later be read by an attacker, or left
floating around in memory for later retrieval.

For this reason the library uses a ``std::vector`` with a custom
allocator that will zero memory before deallocation, named via typedef
as ``secure_vector``. Because it is simply a STL vector with a custom
allocator, it has an identical API to the ``std::vector`` you know and
love.

Some operating systems offer the ability to lock memory into RAM,
preventing swapping from occurring. Typically this operation is
restricted to privileged users (root or admin), however some OSes
including Linux and FreeBSD allow normal users to lock a small amount
of memory. On these systems, allocations first attempt to allocate out
of this small locked pool, and then if that fails will fall back to
normal heap allocations.

The ``secure_vector`` template is only meant for primitive data types
(bytes or ints): if you want a container of higher level Botan
objects, you can just use a ``std::vector``, since these objects know
how to clear themselves when they are destroyed. You cannot, however,
have a ``std::vector`` (or any other container) of ``Pipe`` objects or
filters, because these types have pointers to other filters, and
implementing copy constructors for these types would be both hard and
quite expensive (vectors of pointers to such objects is fine, though).
