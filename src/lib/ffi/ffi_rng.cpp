/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_rng.h>
#include <botan/system_rng.h>
#include <botan/auto_rng.h>

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   #include <botan/processor_rng.h>
#endif

extern "C" {

using namespace Botan_FFI;

int botan_rng_init(botan_rng_t* rng_out, const char* rng_type)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(rng_out == nullptr)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      const std::string rng_type_s(rng_type ? rng_type : "system");

      std::unique_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type_s == "system")
         {
         rng.reset(new Botan::System_RNG);
         }
      else if(rng_type_s == "user" || rng_type_s == "user-threadsafe")
         {
         rng.reset(new Botan::AutoSeeded_RNG);
         }
      else if(rng_type_s == "null")
         {
         rng.reset(new Botan::Null_RNG);
         }
#if defined(BOTAN_HAS_PROCESSOR_RNG)
      else if((rng_type_s == "rdrand" || rng_type_s == "hwrng") && Botan::Processor_RNG::available())
         {
         rng.reset(new Botan::Processor_RNG);
         }
#endif

      if(!rng)
         {
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
         }

      *rng_out = new botan_rng_struct(rng.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_rng_destroy(botan_rng_t rng)
   {
   return BOTAN_FFI_CHECKED_DELETE(rng);
   }

int botan_rng_get(botan_rng_t rng, uint8_t* out, size_t out_len)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, { r.randomize(out, out_len); });
   }

int botan_rng_reseed(botan_rng_t rng, size_t bits)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, { r.reseed_from_rng(Botan::system_rng(), bits); });
   }

int botan_rng_add_entropy(botan_rng_t rng, const uint8_t* input, size_t len)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, { r.add_entropy(input, len); });
   }

int botan_rng_reseed_from_rng(botan_rng_t rng, botan_rng_t source_rng, size_t bits)
   {
   return BOTAN_FFI_DO(Botan::RandomNumberGenerator, rng, r, { r.reseed_from_rng(safe_get(source_rng), bits); });
   }

}
