/*
* PKCS#11 Session
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_types.h>

namespace Botan::PKCS11 {

Session::Session(Slot& slot, bool read_only) :
      Session(slot, PKCS11::flags(Flag::SerialSession | (read_only ? Flag::None : Flag::RwSession)), nullptr, nullptr) {
}

Session::Session(Slot& slot, Flags flags, VoidPtr callback_data, Notify notify_callback) :
      m_slot(slot), m_handle(0), m_logged_in(false) {
   module()->C_OpenSession(m_slot.slot_id(), flags, callback_data, notify_callback, &m_handle);
}

Session::Session(Slot& slot, SessionHandle handle) : m_slot(slot), m_handle(handle) {
   SessionInfo info = get_info();
   if(info.state == static_cast<CK_STATE>(SessionState::RoPublicSession) ||
      info.state == static_cast<CK_STATE>(SessionState::RwPublicSession)) {
      m_logged_in = false;
   } else {
      m_logged_in = true;
   }
}

Session::~Session() noexcept {
   try {
      if(m_handle) {
         if(m_logged_in) {
            module()->C_Logout(m_handle, nullptr);
         }
         module()->C_CloseSession(m_handle, nullptr);
         m_handle = 0;
      }
   } catch(...) {
      // exception during noexcept destructor is ignored
   }
}

SessionHandle Session::release() {
   SessionHandle handle = 0;
   std::swap(handle, m_handle);
   return handle;
}

void Session::login(UserType user_type, const secure_string& pin) {
   module()->C_Login(m_handle, user_type, pin);
   m_logged_in = true;
}

void Session::logoff() {
   module()->C_Logout(m_handle);
   m_logged_in = false;
}

SessionInfo Session::get_info() const {
   SessionInfo info;
   module()->C_GetSessionInfo(m_handle, &info);
   return info;
}

// NOLINTNEXTLINE(readability-make-member-function-const)
void Session::set_pin(const secure_string& old_pin, const secure_string& new_pin) {
   module()->C_SetPIN(m_handle, old_pin, new_pin);
}

// NOLINTNEXTLINE(readability-make-member-function-const)
void Session::init_pin(const secure_string& new_pin) {
   module()->C_InitPIN(m_handle, new_pin);
}

}  // namespace Botan::PKCS11
