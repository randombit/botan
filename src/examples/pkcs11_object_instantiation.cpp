#include <botan/p11.h>

int main()
   {
   Botan::Dynamically_Loaded_Library pkcs11_module( "C:\\pkcs11-middleware\\library.dll" );
   Botan::PKCS11::FunctionListPtr func_list = nullptr;
   Botan::PKCS11::LowLevel::C_GetFunctionList( pkcs11_module, &func_list );
   Botan::PKCS11::LowLevel p11_low_level( func_list );
   }
