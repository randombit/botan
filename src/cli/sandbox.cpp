/*
* (C) 2019 David Carlier <devnexen@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "sandbox.h"
#include <botan/build.h>

#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
  #include <unistd.h>
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
  #include <sys/capsicum.h>
#endif

namespace Botan_CLI {

Sandbox::Sandbox()
   {
#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
   m_name = "pledge";
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
   m_name = "capsicum";
#else
   m_name = "<none>";
#endif
   }

bool Sandbox::init()
   {
#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
   const static char *opts = "stdio rpath inet error";
   return (::pledge(opts, nullptr) == 0);
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
   return (::cap_enter() == 0);
#else
   return true;
#endif
   }

Sandbox::~Sandbox()
   {
   }
}
