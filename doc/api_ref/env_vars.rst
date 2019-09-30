Environment Variables
======================

Certain environment variables can affect or tune the behavior of the
library. The variables and their behavior are described here.

* ``BOTAN_THREAD_POOL_SIZE`` controls the number of threads which will be
  created for a thread pool used for some purposes within the library. If not
  set then it defaults to the number of CPUs available on the system.

* ``BOTAN_MLOCK_POOL_SIZE`` controls the total amount of memory which will be
  locked in memory using ``mlock`` or ``VirtualLock`` and managed in a memory
  pool. If set to ``0`` (or indeed any value smaller than the system page size),
  then the memory pool is disabled.

* ``BOTAN_FFI_PRINT_EXCEPTIONS`` if this variable is set (to any value), then
  if an exception is caught by the FFI layer, before returning an error code, it
  will print the text message of the exception to stderr. This is primarily
  intended for debugging.

