/*
* Win32 CryptoAPI EntropySource
* (C) 1999-2009,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_capi.h>
#include <botan/parsing.h>
#define NOMINMAX 1
#include <windows.h>
#include <wincrypt.h>

namespace Botan {

namespace {

class CSP_Handle_Impl : public Win32_CAPI_EntropySource::CSP_Handle
   {
   public:
      explicit CSP_Handle_Impl(u64bit capi_provider)
         {
         m_valid = ::CryptAcquireContext(&m_handle,
                                         0,
                                         0,
                                         static_cast<DWORD>(capi_provider),
                                         CRYPT_VERIFYCONTEXT);
         }

      ~CSP_Handle_Impl()
         {
         if(m_valid)
            ::CryptReleaseContext(m_handle, 0);
         }

      size_t gen_random(byte out[], size_t n) const
         {
         if(m_valid && ::CryptGenRandom(m_handle, static_cast<DWORD>(n), out))
            return n;
         return 0;
         }

   private:
      bool m_valid;
      HCRYPTPROV m_handle;
   };

}

/*
* Gather Entropy from Win32 CAPI
*/
size_t Win32_CAPI_EntropySource::poll(RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);
   size_t bits = 0;

   for(size_t i = 0; i != m_csp_provs.size(); ++i)
      {
      size_t got = m_csp_provs[i]->gen_random(buf.data(), buf.size());

      if(got > 0)
         {
         rng.add_entropy(buf.data(), got);
         bits += got * 8;
         }
      }

   return bits;
   }

/*
* Win32_Capi_Entropysource Constructor
*/
Win32_CAPI_EntropySource::Win32_CAPI_EntropySource(const std::string& provs)
   {
   for(std::string prov_name : split_on(provs, ':'))
      {
      DWORD prov_type;

      if(prov_name == "RSA_FULL")
         prov_type = PROV_RSA_FULL;
      else if(prov_name == "INTEL_SEC")
         prov_type = PROV_INTEL_SEC;
      else if(prov_name == "RNG")
         prov_type = PROV_RNG;
      else
         continue;

      m_csp_provs.push_back(std::unique_ptr<CSP_Handle>(new CSP_Handle_Impl(prov_type)));
      }
   }

}
