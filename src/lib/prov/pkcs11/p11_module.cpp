/*
* PKCS#11 Module
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_module.h>

namespace Botan {

namespace PKCS11 {

Module::Module(const std::string& file_path, C_InitializeArgs init_args)
   : m_file_path(file_path)
   {
   reload(init_args);
   }

Module::~Module() BOTAN_NOEXCEPT
   {
   try
      {
      m_low_level->C_Finalize(nullptr, nullptr);
      }
   catch(...)
      {
      // we are noexcept and must swallow any exception here
      }
   }

void Module::reload(C_InitializeArgs init_args)
   {
   if(m_low_level)
      {
      m_low_level->C_Finalize(nullptr);
      }

   m_library.reset(new Dynamically_Loaded_Library(m_file_path));
   LowLevel::C_GetFunctionList(*m_library, &m_func_list);
   m_low_level.reset(new LowLevel(m_func_list));

   m_low_level->C_Initialize(&init_args);
   }

}
}
