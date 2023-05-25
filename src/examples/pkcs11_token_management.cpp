#include <botan/p11.h>
#include <botan/p11_types.h>

#include <vector>

int main() {
   /************ set pin *************/

   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");

   // only slots with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);

   // use first slot
   Botan::PKCS11::Slot slot(module, slots.at(0));

   Botan::PKCS11::secure_string so_pin = {'1', '2', '3', '4', '5', '6', '7', '8'};
   Botan::PKCS11::secure_string pin = {'1', '2', '3', '4', '5', '6'};
   Botan::PKCS11::secure_string test_pin = {'6', '5', '4', '3', '2', '1'};

   // set pin
   Botan::PKCS11::set_pin(slot, so_pin, test_pin);

   // change back
   Botan::PKCS11::set_pin(slot, so_pin, pin);

   /************ initialize *************/
   Botan::PKCS11::initialize_token(slot, "Botan handbook example", so_pin, pin);

   /************ change pin *************/
   Botan::PKCS11::change_pin(slot, pin, test_pin);

   // change back
   Botan::PKCS11::change_pin(slot, test_pin, pin);

   /************ change security officer pin *************/
   Botan::PKCS11::change_so_pin(slot, so_pin, test_pin);

   // change back
   Botan::PKCS11::change_so_pin(slot, test_pin, so_pin);

   return 0;
}
