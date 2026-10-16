.. _thread_pool:

Thread Pool
========================================

Some operations split their work across multiple threads. Currently this
includes RSA private key operations, Argon2 with more than one lane, and the
batched hashing used by several post-quantum schemes (for instance XMSS, HSS/LMS
and SLH-DSA). By default such work runs on a thread pool internal to the
library. Its threads are started on first use, and its size can be controlled
with the ``BOTAN_THREAD_POOL_SIZE`` environment variable (see :ref:`env_vars`).

.. versionadded:: 3.14.0

An application which already has a thread pool of its own, or which needs to
control which threads the library uses, can instead install an executor. The
interface is declared in ``work_executor.h``:

.. cpp:class:: Work_Executor

   .. cpp:function:: void queue_work(std::function<void()> work)

      Queue a piece of work. The work must run exactly once, on any thread.
      Running it directly within this call is permitted. If this call throws,
      the work is taken to not have been accepted, and the library runs it in
      the calling thread instead. The work never throws.

   .. cpp:function:: size_t max_concurrency() const

      Return the number of threads available to run queued work. This is a hint
      used to decide how finely divisible work is split. Returning 1 means such
      work is not split at all, though the executor may still be asked to run
      work which is parallel by nature (such as the lanes of Argon2). It is
      queried when the executor is installed.

   .. cpp:function:: static void set_global(std::shared_ptr<Work_Executor> executor)

      Install an executor, replacing the internal thread pool. This may be
      called at most once; the executor then remains in use, and is referenced
      by the library, for the remainder of the process. Any threads the
      internal pool has already started finish their queued work and exit, so
      ideally this is called before any other use of the library, in which
      case those threads are never started at all.

      Throws ``Invalid_State`` if an executor is already installed, or if
      called from within work queued by the library.

All work the library queues is fork-join: the thread which queued it blocks
until it has completed. The executor must therefore guarantee forward progress.
Each piece of work must either run on a thread which is not itself blocked
waiting for it, or be run directly within ``queue_work``. Two cases deserve
particular care:

* An executor backed by a fixed set of threads should run work directly when
  ``queue_work`` is called from one of those threads. Otherwise, if every such
  thread is inside a library operation waiting on work it queued, none of that
  work can ever run.

* An event loop run by a single thread (such as a ``boost::asio::io_context``)
  must not be used as the executor from that same thread, since the queued work
  cannot run while the thread is blocked waiting for it.

The library itself handles the nested case: work queued from within work the
library is already running on the executor is run directly.

All work queued by the library is non-blocking computationally bound tasks.
It is probably inadvisable to execute this work on an application I/O thread
pool.

Both ``queue_work`` and ``max_concurrency`` may be called from any number of
threads at once, and so must be thread safe.

The library's reference to the executor is released during static destruction
at process exit. If that is the last reference the executor is destroyed at that
point, possibly while its threads are still running work on behalf of other
application threads. An application which wants to control when its executor is
destroyed should keep a reference of its own. Independent of this, and as with
the internal pool, any thread which may be inside a library operation must be
joined before the process exits.

An executor whose ``queue_work`` simply invokes the work and whose
``max_concurrency`` returns 1 disables threading entirely, which is the
programmatic equivalent of setting ``BOTAN_THREAD_POOL_SIZE`` to ``none``.

Code Example
------------

The following example adapts a fixed size ``boost::asio::thread_pool``,
installs it, and runs Argon2 through it.

.. literalinclude:: /../src/examples/thread_pool_executor.cpp
   :language: cpp
