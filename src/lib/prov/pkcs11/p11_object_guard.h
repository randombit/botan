/*
* PKCS#11 Object Guard
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_P11_OBJECT_GUARD_H_
#define BOTAN_P11_OBJECT_GUARD_H_

#include <botan/p11_types.h>
#include <initializer_list>
#include <vector>

namespace Botan::PKCS11 {

/**
* Destroys newly created token objects unless released, so that a failure
* after creating an object (for example while reading back its attributes)
* does not leave an unreachable object behind on the token.
*/
class Object_Creation_Guard final {
   public:
      Object_Creation_Guard(Session& session, std::initializer_list<ObjectHandle> handles) :
            m_session(session), m_handles(handles) {}

      ~Object_Creation_Guard() noexcept {
         for(const auto handle : m_handles) {
            try {
               m_session.module()->C_DestroyObject(m_session.handle(), handle, nullptr);
            } catch(...) {  // NOLINT(*-empty-catch)
            }
         }
      }

      /// Call once construction has succeeded
      void release() { m_handles.clear(); }

      Object_Creation_Guard(const Object_Creation_Guard&) = delete;
      Object_Creation_Guard& operator=(const Object_Creation_Guard&) = delete;
      Object_Creation_Guard(Object_Creation_Guard&&) = delete;
      Object_Creation_Guard& operator=(Object_Creation_Guard&&) = delete;

   private:
      Session& m_session;
      std::vector<ObjectHandle> m_handles;
};

}  // namespace Botan::PKCS11

#endif
