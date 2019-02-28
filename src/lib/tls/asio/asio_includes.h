/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_INCLUDES_H_
#define BOTAN_ASIO_INCLUDES_H_

#ifdef BOTAN_HAS_BOOST_ASIO

// We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
// which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
#define BOOST_ASIO_DISABLE_SERIAL_PORT
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#endif // BOTAN_HAS_BOOST_ASIO
#endif // BOTAN_ASIO_INCLUDES_H_
