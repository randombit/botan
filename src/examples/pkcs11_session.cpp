#include <botan/p11.h>
#include <botan/p11_types.h>

#include <iostream>
#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");
   // use first slot with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);
   Botan::PKCS11::Slot slot(module, slots.at(0));

   // open read only session
   { Botan::PKCS11::Session read_only_session(slot, true); }

   // open read write session
   { Botan::PKCS11::Session read_write_session(slot, false); }

   // open read write session by passing flags
   {
      Botan::PKCS11::Flags flags =
         Botan::PKCS11::flags(Botan::PKCS11::Flag::SerialSession | Botan::PKCS11::Flag::RwSession);

      Botan::PKCS11::Session read_write_session(slot, flags, nullptr, nullptr);
   }

   // move ownership of a session
   {
      Botan::PKCS11::Session session(slot, false);
      Botan::PKCS11::SessionHandle handle = session.release();

      Botan::PKCS11::Session session2(slot, handle);
   }

   Botan::PKCS11::Session session(slot, false);

   // get session info
   Botan::PKCS11::SessionInfo info = session.get_info();
   std::cout << info.slotID << '\n';

   // login
   Botan::PKCS11::secure_string pin = {'1', '2', '3', '4', '5', '6'};
   session.login(Botan::PKCS11::UserType::User, pin);

   // set pin
   Botan::PKCS11::secure_string new_pin = {'6', '5', '4', '3', '2', '1'};
   session.set_pin(pin, new_pin);

   // logoff
   session.logoff();

   // log in as security officer
   Botan::PKCS11::secure_string so_pin = {'0', '0', '0', '0', '0', '0', '0', '0'};
   session.login(Botan::PKCS11::UserType::SO, so_pin);

   // change pin to old pin
   session.init_pin(pin);

   return 0;
}
