#include <botan/p11.h>

int main()
   {
   Botan::PKCS11::LowLevel p11_low_level(func_list);

   Botan::PKCS11::C_InitializeArgs init_args = { nullptr, nullptr, nullptr, nullptr,
            static_cast<CK_FLAGS>(Botan::PKCS11::Flag::OsLockingOk), nullptr };

   p11_low_level.C_Initialize(&init_args);

   // work with the token

   p11_low_level.C_Finalize(nullptr);
   }
