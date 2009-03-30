/*
* Win32 CryptoAPI EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/es_capi.h>
#include <botan/parsing.h>
#include <windows.h>
#include <wincrypt.h>

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

      u32bit gen_random(byte out[], u32bit n) const
         {
         if(is_valid() && CryptGenRandom(handle, n, out))
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

/**
* Gather Entropy from Win32 CAPI
*/
void Win32_CAPI_EntropySource::poll(Entropy_Accumulator& accum)
   {
   MemoryRegion<byte>& io_buffer = accum.get_io_buffer(32);

   for(u32bit j = 0; j != prov_types.size(); ++j)
      {
      CSP_Handle csp(prov_types[j]);

      u32bit got = csp.gen_random(io_buffer.begin(), io_buffer.size());

      if(got)
         {
         accum.add(io_buffer.begin(), io_buffer.size(), 8);
         break;
         }
      }
   }

/**
* Win32_Capi_Entropysource Constructor
*/
Win32_CAPI_EntropySource::Win32_CAPI_EntropySource(const std::string& provs)
   {
   std::vector<std::string> capi_provs = split_on(provs, ':');

   for(u32bit j = 0; j != capi_provs.size(); ++j)
      {
      if(capi_provs[j] == "RSA_FULL")  prov_types.push_back(PROV_RSA_FULL);
      if(capi_provs[j] == "INTEL_SEC") prov_types.push_back(PROV_INTEL_SEC);
      if(capi_provs[j] == "FORTEZZA")  prov_types.push_back(PROV_FORTEZZA);
      if(capi_provs[j] == "RNG")       prov_types.push_back(PROV_RNG);
      }

   if(prov_types.size() == 0)
      prov_types.push_back(PROV_RSA_FULL);
   }

}
