#include <botan/p11.h>
#include <botan/p11_types.h>

#include <iostream>
#include <string>
#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");

   // only slots with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);

   // use first slot
   Botan::PKCS11::Slot slot(module, slots.at(0));

   // print firmware version of the slot
   Botan::PKCS11::SlotInfo slot_info = slot.get_slot_info();
   std::cout << std::to_string(slot_info.firmwareVersion.major) << "."
             << std::to_string(slot_info.firmwareVersion.minor) << '\n';

   // print firmware version of the token
   Botan::PKCS11::TokenInfo token_info = slot.get_token_info();
   std::cout << std::to_string(token_info.firmwareVersion.major) << "."
             << std::to_string(token_info.firmwareVersion.minor) << '\n';

   // retrieve all mechanisms supported by the token
   std::vector<Botan::PKCS11::MechanismType> mechanisms = slot.get_mechanism_list();

   // retrieve information about a particular mechanism
   Botan::PKCS11::MechanismInfo mech_info = slot.get_mechanism_info(Botan::PKCS11::MechanismType::RsaPkcsOaep);

   // maximum RSA key length supported:
   std::cout << mech_info.ulMaxKeySize << '\n';

   // initialize the token
   Botan::PKCS11::secure_string so_pin(8, '0');
   slot.initialize("Botan PKCS11 documentation test label", so_pin);

   return 0;
}
