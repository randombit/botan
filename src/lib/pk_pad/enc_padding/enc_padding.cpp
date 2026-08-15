/*
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/enc_padding.h>

#include <botan/exceptn.h>
#include <botan/pk_options.h>

#if defined(BOTAN_HAS_EME_OAEP)
   #include <botan/internal/oaep.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1)
   #include <botan/internal/eme_pkcs.h>
#endif

#if defined(BOTAN_HAS_EME_RAW)
   #include <botan/internal/eme_raw.h>
#endif

namespace Botan {

std::unique_ptr<EncryptionPaddingScheme> EncryptionPaddingScheme::create_or_throw(
   const PK_Encryption_Options& options) {
   // Encrypting without padding is dangerous, so it must be requested explicitly
   if(!options.using_padding()) {
      throw Lookup_Error("Public key encryption requires specifying a padding scheme");
   }

   const std::string padding = options.padding().value();

   // Any option not examined by the selected scheme is rejected by the caller

#if defined(BOTAN_HAS_EME_RAW)
   if(padding == "Raw") {
      return std::make_unique<EME_Raw>();
   }
#endif

#if defined(BOTAN_HAS_EME_PKCS1)
   if(padding == "PKCS1v15") {
      return std::make_unique<EME_PKCS1v15>();
   }
#endif

#if defined(BOTAN_HAS_EME_OAEP)
   if(padding == "OAEP") {
      return std::make_unique<OAEP>(options);
   }
#endif

   throw Lookup_Error("Invalid or unavailable encryption padding scheme " + options.to_string());
}

EncryptionPaddingScheme::~EncryptionPaddingScheme() = default;

}  // namespace Botan
