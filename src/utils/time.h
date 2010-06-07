/*
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

/**
* Struct representing a particular date and time
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

/**
* @param time_point a time point from the system clock
* @returns calendar_point object representing this time point
*/
BOTAN_DLL calendar_point calendar_value(u64bit time_point);

/**
* @return seconds resolution timestamp, unknown epoch
*/
BOTAN_DLL u64bit system_time();

/**
* @return nanoseconds resolution timestamp, unknown epoch
*/
BOTAN_DLL u64bit get_nanoseconds_clock();

}

#endif
