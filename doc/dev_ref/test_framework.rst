Test Framework
================

Botan uses a custom-built test framework. Some portions of it are
quite similar to assertion-based test frameworks such as Catch or
Gtest, but it also includes many features which are well suited for
testing cryptographic algorithms.

The intent is that the test framework and the test suite evolve
symbiotically; as a general rule of thumb if a new function would make
the implementation of just two distinct tests simpler, it is worth
adding to the framework on the assumption it will prove useful again.
Feel free to propose changes to the test system.

When writing a new test, there are three key classes that are used,
namely ``Test``, ``Test::Result``, and ``Text_Based_Test``. A ``Test``
(or ``Test_Based_Test``) runs and returns one or more ``Test::Result``.

Namespaces in Test
-------------------

The test code lives in a distinct namespace (``Botan_Tests``) and all
code in the tests which calls into the library should use the
namespace prefix ``Botan::`` rather than a ``using namespace``
declaration. This makes it easier to see where the test is actually
invoking the library, and makes it easier to reuse test code for
applications.

Test Data
-----------

The test framework is heavily data driven. As of this writing, there
is about 1 Mib of test code and 17 MiB of test data. For most (though
certainly not all) tests, it is better to add a data file representing
the input and outputs, and run the tests over it. Data driven tests
make adding or editing tests easier, for example by writing scripts
which produce new test data and output it in the expected format.

Test
--------

.. cpp:class:: Test

  .. cpp:function:: virtual std::vector<Test::Result> run() = 0

     This is the key function of a ``Test``: it executes and returns a
     list of results. Almost all other functions on ``Test`` are
     static functions which just serve as helper functions for ``run``.

  .. cpp:function:: static std::string read_data_file(const std::string& path)

     Return the contents of a data file and return it as a string.

  .. cpp:function:: static std::vector<uint8_t> read_binary_data_file(const std::string& path)

     Return the contents of a data file and return it as a vector of
     bytes.

  .. cpp:function:: static std::string data_file(const std::string& what)

     An alternative to ``read_data_file`` and ``read_binary_file``,
     use only as a last result, typically for library APIs which
     themselves accept a filename rather than a data blob.

  .. cpp:function:: static bool run_long_tests() const

     Returns true if the user gave option ``--run-long-tests``. Use
     this to gate particularly time-intensive tests.

  .. cpp:function:: static Botan::RandomNumberGenerator& rng()

     Returns a reference to a fast, not cryptographically secure
     random number generator. It is deterministicly seeded with the
     seed logged by the test runner, so it is possible to reproduce
     results in "random" tests.

Tests are registered using the macro ``BOTAN_REGISTER_TEST`` which
takes 2 arguments: the name of the test and the name of the test class.
For example given a ``Test`` instance named ``MyTest``, use::

  BOTAN_REGISTER_TEST("mytest", MyTest);

All test names should contain only lowercase letters, numbers, and
underscore.

Test::Result
-------------

.. cpp:class:: Test::Result

    A ``Test::Result`` records one or more tests on a particular topic
    (say "AES-128/CBC" or "ASN.1 date parsing"). Most of the test functions
    return true or false if the test was successful or not; this allows
    performing conditional blocks as a result of earlier tests::

      if(result.test_eq("first value", produced, expected))
         {
         // further tests that rely on the initial test being correct
         }

    Only the most commonly used functions on ``Test::Result`` are documented here,
    see the header ``tests.h`` for more.

    .. cpp:function:: Test::Result(const std::string& who)

       Create a test report on a particular topic. This will be displayed in the
       test results.

    .. cpp:function:: bool test_success()

       Report a test that was successful.

    .. cpp:function:: bool test_success(const std::string& note)

       Report a test that was successful, including some comment.

    .. cpp:function:: bool test_failure(const std::string& err)

       Report a test failure of some kind. The error string will be logged.

    .. cpp:function:: bool test_failure(const std::string& what, const std::string& error)

       Report a test failure of some kind, with a description of what failed and
       what the error was.

    .. cpp:function:: void test_failure(const std::string& what, const uint8_t buf[], size_t buf_len)

       Report a test failure due to some particular input, which is provided as
       arguments. Normally this is only used if the test was using some
       randomized input which unexpectedly failed, since if the input is
       hardcoded or from a file it is easier to just reference the test number.

    .. cpp:function:: bool test_eq(const std::string& what, const std::string& produced, const std::string& expected)

       Compare to strings for equality.

    .. cpp:function:: bool test_ne(const std::string& what, const std::string& produced, const std::string& expected)

       Compare to strings for non-equality.

    .. cpp:function:: bool test_eq(const char* producer, const std::string& what, \
                                   const uint8_t produced[], size_t produced_len, \
                                   const uint8_t expected[], size_t expected_len)

       Compare two arrays for equality.

    .. cpp:function:: bool test_ne(const char* producer, const std::string& what, \
                                   const uint8_t produced[], size_t produced_len, \
                                   const uint8_t expected[], size_t expected_len)

       Compare two arrays for non-equality.

    .. cpp:function:: bool test_eq(const std::string& producer, const std::string& what, \
                                   const std::vector<uint8_t>& produced, \
                                   const std::vector<uint8_t>& expected)

       Compare two vectors for equality.

    .. cpp:function:: bool test_ne(const std::string& producer, const std::string& what, \
                                   const std::vector<uint8_t>& produced, \
                                   const std::vector<uint8_t>& expected)

       Compare two vectors for non-equality.

    .. cpp:function:: bool confirm(const std::string& what, bool expr)

       Test that some expression evaluates to ``true``.

    .. cpp:function:: template<typename T> bool test_not_null(const std::string& what, T* ptr)

       Verify that the pointer is not null.

    .. cpp:function:: bool test_lt(const std::string& what, size_t produced, size_t expected)

       Test that ``produced`` < ``expected``.

    .. cpp:function:: bool test_lte(const std::string& what, size_t produced, size_t expected)

       Test that ``produced`` <= ``expected``.

    .. cpp:function:: bool test_gt(const std::string& what, size_t produced, size_t expected)

       Test that ``produced`` > ``expected``.

    .. cpp:function:: bool test_gte(const std::string& what, size_t produced, size_t expected)

       Test that ``produced`` >= ``expected``.

    .. cpp:function:: bool test_throws(const std::string& what, std::function<void ()> fn)

       Call a function and verify it throws an exception of some kind.

    .. cpp:function:: bool test_throws(const std::string& what, const std::string& expected, std::function<void ()> fn)

       Call a function and verify it throws an exception of some kind
       and that the exception message exactly equals ``expected``.

Text_Based_Test
-----------------

A ``Text_Based_Text`` runs tests that are produced from a text file
with a particular format which looks somewhat like an INI-file::

  # Comments begin with # and continue to end of line
  [Header]
  # Test 1
  Key1 = Value1
  Key2 = Value2

  # Test 2
  Key1 = Value1
  Key2 = Value2

.. cpp:class:: VarMap

  An object of this type is passed to each invocation of the text-based test.
  It is used to access the test variables. All access takes a key, which is
  one of the strings which was passed to the constructor of ``Text_Based_Text``.
  Accesses are either required (``get_req_foo``), in which case an exception is
  throwing if the key is not set, or optional (``get_opt_foo``) in which case
  the test provides a default value which is returned if the key was not set
  for this particular instance of the test.

  .. cpp:function:: std::vector<uint8_t> get_req_bin(const std::string& key) const

     Return a required binary string. The input is assumed to be hex encoded.

  .. cpp:function:: std::vector<uint8_t> get_opt_bin(const std::string& key) const

     Return an optional binary string. The input is assumed to be hex encoded.

  .. cpp:function:: std::vector<std::vector<uint8_t>> get_req_bin_list(const std::string& key) const

  .. cpp:function:: Botan::BigInt get_req_bn(const std::string& key) const

     Return a required BigInt. The input can be decimal or (with "0x" prefix) hex encoded.

  .. cpp:function:: Botan::BigInt get_opt_bn(const std::string& key, const Botan::BigInt& def_value) const

     Return an optional BigInt. The input can be decimal or (with "0x" prefix) hex encoded.

  .. cpp:function:: std::string get_req_str(const std::string& key) const

     Return a required text string.

  .. cpp:function:: std::string get_opt_str(const std::string& key, const std::string& def_value) const

     Return an optional text string.

  .. cpp:function:: size_t get_req_sz(const std::string& key) const

     Return a required integer. The input should be decimal.

  .. cpp:function:: size_t get_opt_sz(const std::string& key, const size_t def_value) const

     Return an optional integer. The input should be decimal.

.. cpp:class:: Text_Based_Test : public Test

  .. cpp:function:: Text_Based_Test(const std::string& input_file, \
                    const std::string& required_keys, \
                    const std::string& optional_keys = "")

     This constructor is

     .. note::
        The final element of required_keys is the "output key", that is
        the key which signifies the boundary between one test and the next.
        When this key is seen, ``run_one_test`` will be invoked. In the
        test input file, this key must always appear least for any particular
        test. All the other keys may appear in any order.

  .. cpp:function:: Test::Result run_one_test(const std::string& header, \
                    const VarMap& vars)

     Runs a single test and returns the result of it. The ``header``
     parameter gives the value (if any) set in a ``[Header]`` block.
     This can be useful to distinguish several types of tests within a
     single file, for example "[Valid]" and "[Invalid]".

  .. cpp:function:: bool clear_between_callbacks() const

     By default this function returns ``false``. If it returns
     ``true``, then when processing the data in the file, variables
     are not cleared between tests. This can be useful when several
     tests all use some common parameters.

Test Runner
-------------

If you are simply writing a new test there should be no need to modify
the runner, however it can be useful to be aware of its abilities.

The runner can run tests concurrently across many cores. By default single
threaded execution is used, but you can use ``--test-threads`` option to
specify the number of threads to use. If you use ``--test-threads=0`` then
the runner will probe the number of active CPUs and use that (but limited
to at most 16). If you want to run across many cores on a large machine,
explicitly specify a thread count. The speedup is close to linear.

The RNG used in the tests is deterministic, and the seed is logged for each
execution. You can cause the random sequence to repeat using ``--drbg-seed``
option.

.. note::
   Currently the RNG is seeded just once at the start of execution. So you
   must run the exact same sequence of tests as the original test run in
   order to get reproducible results.

If you are trying to track down a bug that happens only occasionally, two very
useful options are ``--test-runs`` and ``--abort-on-first-fail``. The first
takes an integer and runs the specified test cases that many times. The second
causes abort to be called on the very first failed test. This is sometimes
useful when tracing a memory corruption bug.
