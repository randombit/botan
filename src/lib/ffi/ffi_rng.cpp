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

extern "C" {

using namespace Botan_FFI;

int botan_rng_init(botan_rng_t* rng_out, const char* rng_type)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      BOTAN_ASSERT_ARG_NON_NULL(rng_out);

      const std::string rng_type_s(rng_type ? rng_type : "system");

      std::unique_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type_s == "system")
         rng.reset(new Botan::System_RNG);
      else if(rng_type_s == "user")
         rng.reset(new Botan::AutoSeeded_RNG);
      else
         return BOTAN_FFI_ERROR_BAD_PARAMETER;

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

}
