========================================
Footguns
========================================

This section notes areas where certain usages can cause confusing bugs or problems.

Static Objects
------------------

If you maintain ``static`` variables which hold Botan objects, you will perhaps
find that in some circumstances your application crashes in strange ways on
shutdown. That is because, at least on some operating systems, Botan uses a
locked memory pool as backing storage for the ``secure_vector`` type. This pool
allocates out of pages which have been locked into memory using ``mlock`` or
``VirtualLock`` system calls.

If your variable happens to be destroyed before the pool, all is well. If the
pool happens to be destroyed before the variable, then when the object goes to
free its memory, a crash will occur.

This is basically the famous C++ "Static Initialization Order Fiasco", except
in reverse.

The best course of action is to avoid ``static`` variables. If that is
impossible or inconvenient, one option is to disable the pool, either at build
time (disable the ``locking_allocator`` module) or at runtime. Unfortunately the
runtime setting requires setting an environment variable (see :ref:`env_vars`),
and doing so consistently *prior to static intialization* is not trivial, due to
the previously mentioned fiasco. One option might be to use GCC's
``constructor`` function attribute.

Ideally a more satisfactory solution to this issue could be found, especially
given the difficulty of disabling the pool at runtime.

Multithreaded Access
----------------------

It is perfectly safe to use the library from multiple threads.

It is *not* safe to use the same object from multiple threads, without some form
of locking.

There are a few exceptions to this rule, which use internal mutexes. This will
be noted in the respective documentation for these types.

Use of `fork`
----------------------

If you use the `fork` syscall in your code, and attempt to use the library in
both processes, likely bad things will happen due to internal locks. You can
avoid this problem by either at build time disabling the features associated
with these locks (namely ``locking_allocator`` and ``thread_utils``) or
disabling them at runtime using :ref:`env_vars`, ideally at the very start of
`main`.
