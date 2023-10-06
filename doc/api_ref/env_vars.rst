.. _env_vars:

Environment Variables
======================

Certain environment variables can affect or tune the behavior of the
library. The variables and their behavior are described here.

* ``BOTAN_THREAD_POOL_SIZE`` controls the number of threads which will be
  created for a thread pool used for some purposes within the library. If not
  set, or set to 0, then it defaults to the number of CPUs available on the
  system. If it is set to the string "none" then the thread pool is disabled;
  instead all work passed to the thread pool will be executed immediately
  by the calling thread.

  As of version 3.2.0, on MinGW the thread pool is by default disabled, due to a
  bug which causes deadlock on application shutdown. Enabling the pool can be
  explicitly requested by setting ``BOTAN_THREAD_POOL_SIZE`` to an integer
  value.

* ``BOTAN_MLOCK_POOL_SIZE`` controls the total amount of memory, in bytes, which
  will be locked in memory using ``mlock`` or ``VirtualLock`` and managed in a
  memory pool. This should be a multiple of the system page size. If set to
  ``0``, then the memory pool is disabled.

* ``BOTAN_FFI_PRINT_EXCEPTIONS`` if this variable is set (to any value), then
  if an exception is caught by the FFI layer, before returning an error code, it
  will print the text message of the exception to stderr. This is primarily
  intended for debugging.

* ``BOTAN_CLEAR_CPUID``: this variable can be set to a comma-separated list of
  CPUID fields to ignore. For example setting ``BOTAN_CLEAR_CPUID=avx2,avx512``
  will cause AVX2 and AVX-512 codepaths to be avoided. Note that disabling basic
  features (notably NEON or SSE2/SSSE3) can cause other higher level features
  like AES-NI to also become disabled.
