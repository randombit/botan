/*
* (C) 2015,2017 Jack Lloyd
* (C) 2021 René Fischer
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_rng.h>
#include <botan/system_rng.h>
#include <botan/auto_rng.h>

#include <functional>

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

int botan_rng_init_custom(botan_rng_t* rng_out, const char* rng_name, void* context,
                          int(* get_cb)(void* context, uint8_t* out, size_t out_len),
                          int(* add_entropy_cb)(void* context, const uint8_t input[], size_t length),
                          void(* destroy_cb)(void* context))
{
return ffi_guard_thunk(__func__,[=]() -> int {
   if(rng_out == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(rng_name == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   if(get_cb == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   class Custom_RNG : public Botan::RandomNumberGenerator
      {
      public:
         Custom_RNG(const std::string& name, void* context,
                    int(* get_cb)(void* context, uint8_t* out, size_t out_len),
                    int(* add_entropy_cb)(void* context, const uint8_t input[], size_t length),
                    void(* destroy_cb)(void* context)) :
            m_name(name)
            {
               m_context = context;
               m_get_cb = get_cb;
               m_add_entropy_cb = add_entropy_cb;
               m_destroy_cb = destroy_cb;
            }

         ~Custom_RNG()
         {
            if(m_destroy_cb)
            {
               m_destroy_cb(m_context);
            }
         }

         void randomize(uint8_t output[], size_t length) override
         {
            int rc = m_get_cb(m_context, output, length);
            if(rc)
            {
               throw Botan::Invalid_State("Failed to get random from C callback, rc=" + std::to_string(rc));
            }
         }

         bool accepts_input() const override
         {
            return m_add_entropy_cb != nullptr;
         }

         void add_entropy(const uint8_t input[], size_t length) override
         {
            if(m_add_entropy_cb == nullptr)
            {
               return;
            }

            int rc = m_add_entropy_cb(m_context, input, length);
            if(rc)
            {
               throw Botan::Invalid_State("Failed to add entropy via C callback, rc=" + std::to_string(rc));
            }
         }

         std::string name() const override
         {
            return m_name;
         }

         void clear() override
         {
         }

         bool is_seeded() const override
         {
            return true;
         }

      private:
         std::string m_name;
         void* m_context;
         std::function<int(void* context, uint8_t* out, size_t out_len)> m_get_cb;
         std::function<int(void* context, const uint8_t input[], size_t length)> m_add_entropy_cb;
         std::function<void(void* context)> m_destroy_cb;
   };

   std::unique_ptr<Botan::RandomNumberGenerator> rng(new Custom_RNG(rng_name, context, get_cb, add_entropy_cb, destroy_cb));

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
