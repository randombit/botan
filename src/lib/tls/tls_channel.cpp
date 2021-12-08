/*
* TLS Channels
* (C) 2011,2012,2014,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_channel.h>

namespace Botan {

namespace TLS {

size_t TLS::Channel::IO_BUF_DEFAULT_SIZE = 10*1024;

}

}
