/*
* Checks compatibility between the existing headers of Botan and boost
* (C) 2023 Jack Lloyd
*     2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_COMPAT_H_
#define BOTAN_ASIO_COMPAT_H_

#include <botan/build.h>

#if defined(BOTAN_HAS_BOOST_ASIO)

   #include <boost/version.hpp>

   /** @brief minimum supported boost version for the TLS ASIO wrapper
   *
   *  BOOST_VERSION % 100 is the patch level
   *  BOOST_VERSION / 100 % 1000 is the minor version
   *  BOOST_VERSION / 100000 is the major version
   *
   * Botan may still work with older versions of boost. Though, the asio TLS
   * wrapper won't work with versions older than the one specified below.
   *
   * Also note the changelog with rationales for the required versions:
   *
   * until Botan 3.2.0
   *   1.66.0 - first version to be compatible with Networking TS (N4656) and boost::beast
   *
   * as of Botan 3.3.0
   *   1.73.0 - first version supporting the C++20 concepts syntax
   */
   #define BOTAN_MINIMUM_SUPPORTED_BOOST_ASIO_VERSION 107300

   #if BOOST_VERSION >= BOTAN_MINIMUM_SUPPORTED_BOOST_ASIO_VERSION

      /**
      * Indicates that the local boost and botan headers are compatible.
      */
      #define BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION 1

   #endif

#endif
#endif
