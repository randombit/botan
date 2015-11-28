/*
* Win32 CryptoAPI EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_capi.h>
#include <botan/parsing.h>
#include <windows.h>
#include <wincrypt.h>
#undef min
#undef max

namespace Botan {

namespace {

class CSP_Handle
   {
   public:
      CSP_Handle(u64bit capi_provider)
         {
         valid = false;
         DWORD prov_type = (DWORD)capi_provider;

         if(CryptAcquireContext(&handle, 0, 0,
                                prov_type, CRYPT_VERIFYCONTEXT))
            valid = true;
         }

      ~CSP_Handle()
         {
         if(is_valid())
            CryptReleaseContext(handle, 0);
         }

      size_t gen_random(byte out[], size_t n) const
         {
         if(is_valid() && CryptGenRandom(handle, static_cast<DWORD>(n), out))
            return n;
         return 0;
         }

      bool is_valid() const { return valid; }

      HCRYPTPROV get_handle() const { return handle; }
   private:
      HCRYPTPROV handle;
      bool valid;
   };

}

/*
* Gather Entropy from Win32 CAPI
*/
void Win32_CAPI_EntropySource::poll(Entropy_Accumulator& accum)
   {
   secure_vector<byte>& buf = accum.get_io_buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   for(size_t i = 0; i != prov_types.size(); ++i)
      {
      CSP_Handle csp(prov_types[i]);

      if(size_t got = csp.gen_random(buf.data(), buf.size()))
         {
         accum.add(buf.data(), got, BOTAN_ENTROPY_ESTIMATE_STRONG_RNG);
         break;
         }
      }
   }

/*
* Win32_Capi_Entropysource Constructor
*/
Win32_CAPI_EntropySource::Win32_CAPI_EntropySource(const std::string& provs)
   {
   std::vector<std::string> capi_provs = split_on(provs, ':');

   for(size_t i = 0; i != capi_provs.size(); ++i)
      {
      if(capi_provs[i] == "RSA_FULL")  prov_types.push_back(PROV_RSA_FULL);
      if(capi_provs[i] == "INTEL_SEC") prov_types.push_back(PROV_INTEL_SEC);
      if(capi_provs[i] == "FORTEZZA")  prov_types.push_back(PROV_FORTEZZA);
      if(capi_provs[i] == "RNG")       prov_types.push_back(PROV_RNG);
      }

   if(prov_types.size() == 0)
      prov_types.push_back(PROV_RSA_FULL);
   }

}
