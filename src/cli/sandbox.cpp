/*
* (C) 2019 David Carlier <devnexen@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "sandbox.h"
#include <botan/allocator.h>

#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
   #include <unistd.h>
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
   #include <sys/capsicum.h>
   #include <unistd.h>
#elif defined(BOTAN_TARGET_OS_HAS_SETPPRIV)
   #include <priv.h>
#elif defined(BOTAN_TARGET_OS_HAS_SANDBOX_PROC)
   #include <sandbox.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_TARGET_OS_HAS_SETPPRIV)
struct SandboxPrivDelete {
      void operator()(priv_set_t* ps) {
         ::priv_emptyset(ps);
         ::priv_freeset(ps);
      }
};
#endif

Sandbox::Sandbox() {
#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
   m_name = "pledge";
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
   m_name = "capsicum";
#elif defined(BOTAN_TARGET_OS_HAS_SETPPRIV)
   m_name = "privilege";
#elif defined(BOTAN_TARGET_OS_HAS_SANDBOX_PROC)
   m_name = "sandbox";
#else
   m_name = "<none>";
#endif
}

bool Sandbox::init() {
   Botan::initialize_allocator();

#if defined(BOTAN_TARGET_OS_HAS_PLEDGE)
   const static char* opts = "stdio rpath inet error";
   return (::pledge(opts, nullptr) == 0);
#elif defined(BOTAN_TARGET_OS_HAS_CAP_ENTER)
   cap_rights_t wt, rd;

   if(::cap_rights_init(&wt, CAP_READ, CAP_WRITE) == nullptr) {
      return false;
   }

   if(::cap_rights_init(&rd, CAP_FCNTL, CAP_EVENT, CAP_READ) == nullptr) {
      return false;
   }

   if(::cap_rights_limit(STDOUT_FILENO, &wt) == -1) {
      return false;
   }

   if(::cap_rights_limit(STDERR_FILENO, &wt) == -1) {
      return false;
   }

   if(::cap_rights_limit(STDIN_FILENO, &rd) == -1) {
      return false;
   }

   return (::cap_enter() == 0);
#elif defined(BOTAN_TARGET_OS_HAS_SETPPRIV)
   priv_set_t* tmp;
   std::unique_ptr<priv_set_t, SandboxPrivDelete> ps;
   const char* const priv_perms[] = {
      PRIV_PROC_FORK,
      PRIV_PROC_EXEC,
      PRIV_PROC_INFO,
      PRIV_PROC_SESSION,
   };

   if((tmp = ::priv_allocset()) == nullptr) {
      return false;
   }

   ps = std::unique_ptr<priv_set_t, SandboxPrivDelete>(tmp);
   ::priv_basicset(ps.get());

   for(auto perm : priv_perms) {
      if(::priv_delset(ps.get(), perm) == -1) {
         return false;
      }
   }

   return true;
#elif defined(BOTAN_TARGET_OS_HAS_SANDBOX_PROC)

   BOTAN_DIAGNOSTIC_PUSH
   BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS
   if(::sandbox_init(kSBXProfileNoWriteExceptTemporary, SANDBOX_NAMED, nullptr) < 0) {
      return false;
   }
   BOTAN_DIAGNOSTIC_POP

   return true;
#else
   return true;
#endif
}

Sandbox::~Sandbox() = default;

}  // namespace Botan_CLI
