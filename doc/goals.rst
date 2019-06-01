
Project Goals
================================

Botan seeks to be a broadly applicable library that can be used to implement a
range of secure distributed systems.

The library has the following project goals guiding changes. It does not succeed
in all of these areas in every way just yet, but it describes the system that is
the desired end result. Over time further progress is made in each.

* Secure and reliable. The implementations must of course be correct and well
  tested, and attacks such as side channels and fault attacks should be
  accounted for where necessary. The library should never crash, or invoke
  undefined behavior, regardless of circumstances.

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

* Performance. Botan does not in every case strive to be faster than every other
  software implementation, but performance should be competitive and over time
  new optimizations are identified and applied.

* Support whatever I/O mechanism the application wants. Allow the application to
  control all aspects of how the network is contacted, and ensure the API makes
  asynchronous operations easy to handle. This both insulates Botan from
  system-specific details and allows the application to use whatever networking
  style they please.

* Portability to modern systems. Botan does not run everywhere, and we actually
  do not want it to (see non-goals below). But we do want it to run on anything
  that someone is deploying new applications on. That includes both major
  platforms like Windows, Linux, Android and iOS, and also promising new systems
  such as IncludeOS and Fuchsia.

* Well documented. Ideally every public API would have some place in the manual
  describing its usage.

* Useful command line utility. The botan command line tool should be flexible
  and featured enough to replace similar tools such as ``openssl`` for everyday
  users.

Non-Goals
-------------------------

There are goals some crypto libraries have, but which Botan actively does not
seek to address.

* Deep embedded support. Botan requires a heap, C++ exceptions, and RTTI, and at
  least in terms of performance optimizations effectively assumes a 32 or 64 bit
  processor. It is not suitable for deploying on, say FreeRTOS running on a
  MSP430, or smartcard with an 8 bit CPU and 256 bytes RAM. A larger SoC, such
  as a Cortex-A7 running Linux, is entirely within scope.

* Implementing every crypto scheme in existence. The focus is on algorithms
  which are in practical use in systems deployed now, as well as promising
  algorithms for future deployment. Many algorithms which were of interest
  in the past but never saw widespread deployment and have no compelling
  benefit over other designs have been removed to simplify the codebase.

* Portable to obsolete systems. There is no reason for crypto software to
  support ancient OS platforms like SunOS or Windows 2000, since these unpatched
  systems are completely unsafe anyway. The additional complexity supporting
  such platforms just creates more room for bugs.

* Portable to every C++ compiler ever made. Over time Botan moves forward to
  both take advantage of new language/compiler features, and to shed workarounds
  for dealing with bugs in ancient compilers, allowing further simplifications
  in the codebase. The set of supported compilers is fixed for each new release
  branch, for example Botan 2.x will always support GCC 4.8. But a future 3.x
  release version will likely increase the required versions for all compilers.

* FIPS 140 validation. The primary developer was (long ago) a consultant with a
  NIST approved testing lab. He does not have a positive view of the process or
  results, particularly when it comes to Level 1 software validations. The only
  benefit of a Level 1 validation is to allow for government sales, and the cost
  of validation includes enormous amounts of time and money, adding 'checks'
  that are useless or actively harmful, then freezing the software so security
  updates cannot be applied in the future. It does force a certain minimum
  standard (ie, FIPS Level 1 does assure AES and RSA are probably implemented
  correctly) but this is an issue of interop not security since Level 1 does not
  seriously consider attacks of any kind. Any security budget would be far
  better spent on a review from a specialized crypto consultancy, who would look
  for actual flaws.

  That said it would be easy to add a "FIPS 140" build mode to Botan, which just
  disabled all the builtin crypto and wrapped whatever the most recent OpenSSL
  FIPS module exports.

* Educational purposes. The library code is intended to be easy to read and
  review, and so might be useful in an educational context. However it does not
  contain any toy ciphers (unless you count DES and RC4) nor any tools for
  simple cryptanalysis. Generally the manual and source comments assume previous
  knowledge on the basic concepts involved.

* User proof. Some libraries provide a very high level API in an attempt to save
  the user from themselves. Occasionally they succeed. It would be appropriate
  and useful to build such an API on top of Botan, but Botan itself wants to
  cover a broad set of uses cases and some of these involve having pointy things
  within reach.
