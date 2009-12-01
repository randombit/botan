/**
* Time Functions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIME_H__
#define BOTAN_TIME_H__

#include <botan/types.h>
#include <chrono>

namespace Botan {

/*
* Time Conversion Functions
*/
struct BOTAN_DLL calendar_point
   {
   u32bit year;
   byte month;
   byte day;
   byte hour;
   byte minutes;
   byte seconds;

   calendar_point(u32bit y, byte mon, byte d, byte h, byte min, byte sec) :
      year(y), month(mon), day(d), hour(h), minutes(min), seconds(sec) {}
   };

/*
* @param time_point a time point from the system clock
* @returns calendar_point object representing this time point
*/
BOTAN_DLL calendar_point calendar_value(
   const std::chrono::system_clock::time_point& time_point);

/**
@return nanoseconds resolution timestamp, unknown epoch
*/
BOTAN_DLL u64bit get_nanoseconds_clock();

}

#endif
