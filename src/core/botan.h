/*************************************************
* Botan Core Interface Header File               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/init.h>
#include <botan/lookup.h>
#include <botan/rng.h>
#include <botan/version.h>
#include <botan/parsing.h>

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
  #include <botan/auto_rng.h>
#endif
