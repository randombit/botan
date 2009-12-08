/**
* Time Functions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIME_H__
#define BOTAN_TIME_H__

#include <botan/types.h>
#include <ctime>

namespace Botan {

/*
* Time Access/Conversion Functions
*/
BOTAN_DLL u64bit system_time();

BOTAN_DLL std::tm time_t_to_tm(u64bit);

/**
@return nanoseconds resolution timestamp, unknown epoch
*/
BOTAN_DLL u64bit get_nanoseconds_clock();

}

#endif
