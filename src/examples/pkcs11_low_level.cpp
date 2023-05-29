#include <botan/p11.h>
#include <botan/p11_types.h>

#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");

   // C_Initialize is automatically called by the constructor of the Module

   // work with the token

   std::vector<Botan::PKCS11::SlotId> slot_ids;
   [[maybe_unused]] bool success = module->C_GetSlotList(true, slot_ids);

   // C_Finalize is automatically called by the destructor of the Module

   return 0;
}
