/*
 * SPHINCS+ Parameters
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/exceptn.h>
#include <botan/sp_parameters.h>
#include <botan/internal/fmt.h>

namespace Botan {

Sphincs_Parameter_Set Sphincs_Parameters::set_from_name(std::string_view name)
   {
   if(name == "SPHINCS+_128_SMALL_SHA256" || name == "SPHINCS+_128_SMALL_SHAKE256" || name == "SPHINCS+_128_SMALL_HARAKA")
      return Sphincs_Parameter_Set::Sphincs128Small;
   if(name == "SPHINCS+_128_FAST_SHA256" || name == "SPHINCS+_128_FAST_SHAKE256" || name == "SPHINCS+_128_FAST_HARAKA")
      return Sphincs_Parameter_Set::Sphincs128Fast;

   if(name == "SPHINCS+_192_SMALL_SHA256" || name == "SPHINCS+_192_SMALL_SHAKE256" || name == "SPHINCS+_192_SMALL_HARAKA")
      return Sphincs_Parameter_Set::Sphincs192Small;
   if(name == "SPHINCS+_192_FAST_SHA256" || name == "SPHINCS+_192_FAST_SHAKE256" || name == "SPHINCS+_192_FAST_HARAKA")
      return Sphincs_Parameter_Set::Sphincs192Fast;

   if(name == "SPHINCS+_256_SMALL_SHA256" || name == "SPHINCS+_256_SMALL_SHAKE256" || name == "SPHINCS+_256_SMALL_HARAKA")
      return Sphincs_Parameter_Set::Sphincs256Small;
   if(name == "SPHINCS+_256_FAST_SHA256" || name == "SPHINCS+_256_FAST_SHAKE256" || name == "SPHINCS+_256_FAST_HARAKA")
      return Sphincs_Parameter_Set::Sphincs256Fast;

   throw Lookup_Error(fmt("No SPHINCS+ parameter set found for: {}", name));
   }

Sphincs_Hash_Type Sphincs_Parameters::hash_from_name(std::string_view name)
   {
   if(name == "SPHINCS+_128_SMALL_SHA256" ||
      name == "SPHINCS+_128_FAST_SHA256"  ||
      name == "SPHINCS+_192_SMALL_SHA256" ||
      name == "SPHINCS+_192_FAST_SHA256"  ||
      name == "SPHINCS+_256_SMALL_SHA256" ||
      name == "SPHINCS+_256_FAST_SHA256")
      return Sphincs_Hash_Type::Sha256;
   if(name == "SPHINCS+_128_SMALL_SHAKE256" ||
      name == "SPHINCS+_128_FAST_SHAKE256"  ||
      name == "SPHINCS+_192_SMALL_SHAKE256" ||
      name == "SPHINCS+_192_FAST_SHAKE256"  ||
      name == "SPHINCS+_256_SMALL_SHAKE256" ||
      name == "SPHINCS+_256_FAST_SHAKE256")
      return Sphincs_Hash_Type::Shake256;
   if(name == "SPHINCS+_128_SMALL_HARAKA" ||
      name == "SPHINCS+_128_FAST_HARAKA"  ||
      name == "SPHINCS+_192_SMALL_HARAKA" ||
      name == "SPHINCS+_192_FAST_HARAKA"  ||
      name == "SPHINCS+_256_SMALL_HARAKA" ||
      name == "SPHINCS+_256_FAST_HARAKA")
      return Sphincs_Hash_Type::Haraka;

   throw Lookup_Error(fmt("No SPHINCS+ hash instantiation found for: {}", name));
   }

std::string Sphincs_Parameters::hash_name() const
   {
   switch(m_hash_type)
      {
      case Sphincs_Hash_Type::Sha256:
         return "SHA-256";
      case Sphincs_Hash_Type::Shake256:
         return fmt("SHAKE-256({})", 8 * n());
      case Sphincs_Hash_Type::Haraka:
         return "Haraka";
      }

   Botan::unreachable();
   }

}
