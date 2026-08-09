
Project Goals
================================

Botan seeks to be a broadly applicable library that can be used to implement a
range of secure distributed systems. The library has the following project goals
guiding changes.

* Secure and reliable. The implementations must of course be correct and well
  tested, and attacks such as side channels and fault attacks should be
  accounted for where necessary. The library should never crash, or invoke
  undefined behavior, regardless of circumstances.

* Constant time programming. The table stakes for a modern cryptographic library
  include being immune to basic timing/cache based side channels. Botan includes
  utilities to assist in writing and testing constant time code. A test suite
  run nightly in CI verifies Botan's constant time behavior across a range of
  compilers, compiler options, and CPU architectures.

* Implement schemes important in practice. It should be practical to implement
  any real-world crypto protocol using just what the library provides. It is
  worth some (limited) additional complexity in the library, in order to expand
  the set of applications which can easily adopt Botan.

* Ease of use. It should be straightforward for an application programmer to do
  whatever it is they need to do. There should be one obvious way to perform any
  operation. The API should be predicable, and follow the "principle of least
  astonishment" in its design. This is not just a nicety; confusing APIs often
  result in errors that end up compromising security.

* Simplicity of design, clarity of code, ease of review. The code should be easy
  to read and understand by other library developers, users seeking to better
  understand the behavior of the code, and by professional reviewers looking for
  bugs. This is important because bugs in convoluted code can easily escape
  multiple expert reviews, and end up living on for years.

* Well tested. The code should be correct against the spec, with as close to
  100% test coverage as possible. All available static and dynamic analysis
  tools at our disposal should be used, including fuzzers, symbolic execution,
  and protocol specific tools. Within reason, all warnings from compilers and
  static analyzers should be addressed, even if they seem like false positives,
  because that maximizes the signal value of new warnings from the tool.

* Safe defaults. Policies should aim to be highly restrictive by default, and if
  they must be made less restrictive by certain applications, it should be
  obvious to the developer that they are doing something unsafe.

* Post quantum security. Possibly a practical quantum computer that can break
  RSA and ECC will never be built, but the future is notoriously hard to predict.
  It seems prudent to begin designing and deploying systems now which have at
  least the option of using a post-quantum scheme. Botan provides a conservative
  selection of algorithms thought to be post-quantum secure.

* Performance. Botan aims to have the fastest possible implementation of all
  algorithms it supports, subject to the constraints implicit with the other
  project goals.

* Support whatever I/O mechanism the application wants. Allow the application to
  control all aspects of how the network is contacted, and ensure the API makes
  asynchronous operations easy to handle. This both insulates Botan from
  system-specific details and allows the application to use whatever networking
  style they please.

* Portability to all relevant platforms. Botan supports all major operating
  systems and CPU architectures. Botan has also been used with great success on
  baremetal systems and in operating system kernels.

* Well documented. Ideally every public API would have some place in the manual
  describing its usage.

* Useful command line utility. The ``botan`` command line tool should be flexible
  and featured enough to replace similar tools such as ``openssl`` for everyday
  users.

Non-Goals
-------------------------

There are goals some crypto libraries have, but which Botan actively does not
seek to address.

* Implementing every crypto scheme in existence. The focus is on algorithms
  which are in practical use in systems deployed now, as well as promising
  algorithms for future deployment.

* Portable to obsolete systems. There is no reason for crypto software to
  support ancient OS versions like SunOS or Windows 2000, since such unpatched
  systems are completely unsafe anyway. The additional complexity supporting
  such platforms just creates room for bugs.

* Portable to every C++ compiler ever made. Over time Botan moves forward to
  both take advantage of new language/compiler features, and to shed workarounds
  for dealing with bugs in ancient compilers, allowing further simplifications
  in the codebase. The set of supported compilers is fixed for each new major
  release, for example Botan3 will always support GCC 11.

* User proof. Some libraries provide a very high level API in an attempt to save
  the user from themselves. Occasionally they succeed. It would be appropriate
  and useful to include such an API, but covering a broad set of use cases
  requires a relatively flexible approach.
