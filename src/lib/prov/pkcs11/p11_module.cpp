/*
* PKCS#11 Module
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_types.h>

#include <botan/internal/dyn_load.h>

namespace Botan::PKCS11 {

Module::Module(std::string_view file_path, C_InitializeArgs init_args) : m_file_path(file_path) {
   if(file_path.empty()) {
      throw Invalid_Argument("PKCS11 no module path specified");
   }
   reload(init_args);
}

Module::Module(Module&& other) noexcept = default;

Module::~Module() noexcept {
   try {
      m_low_level->C_Finalize(nullptr, nullptr);
   } catch(...) {
      // we are noexcept and must swallow any exception here
   }
}

void Module::reload(C_InitializeArgs init_args) {
   if(m_low_level) {
      m_low_level->C_Finalize(nullptr);
   }
   m_library = std::make_unique<Dynamically_Loaded_Library>(m_file_path);
   m_low_level = std::make_unique<LowLevel>(InterfaceWrapper::latest_p11_interface(*m_library));

   m_low_level->C_Initialize(&init_args);
}

}  // namespace Botan::PKCS11
