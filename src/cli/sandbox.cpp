/*
* (C) 2019 David Carlier <devnexen@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "sandbox.h"
#include <botan/mem_ops.h>

#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
  #include <unistd.h>
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
  #include <sys/capsicum.h>
  #include <unistd.h>
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
   Botan::initialize_allocator();

#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
   const static char *opts = "stdio rpath inet error";
   return (::pledge(opts, nullptr) == 0);
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
   cap_rights_t wt, rd;

   if (::cap_rights_init(&wt, CAP_READ, CAP_WRITE) == nullptr)
      {
      return false;
      }

   if (::cap_rights_init(&rd, CAP_FCNTL, CAP_EVENT, CAP_READ) == nullptr)
      {
      return false;
      }

   if (::cap_rights_limit(STDOUT_FILENO, &wt) == -1)
      {
      return false;
      }

   if (::cap_rights_limit(STDERR_FILENO, &wt) == -1)
      {
      return false;
      }

   if (::cap_rights_limit(STDIN_FILENO, &rd) == -1)
      {
      return false;
      }

   return (::cap_enter() == 0);
#else
   return true;
#endif
   }

Sandbox::~Sandbox()
   {
   }
}
