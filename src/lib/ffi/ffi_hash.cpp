/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/hash.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_hash_struct, Botan::HashFunction, 0x1F0A4F84);

int botan_hash_init(botan_hash_t* hash, const char* hash_name, uint32_t flags)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(hash == nullptr || hash_name == nullptr || *hash_name == 0)
         return BOTAN_FFI_ERROR_NULL_POINTER;
      if(flags != 0)
         return BOTAN_FFI_ERROR_BAD_FLAG;

      std::unique_ptr<Botan::HashFunction> h = Botan::HashFunction::create(hash_name);
      if(h == nullptr)
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

      *hash = new botan_hash_struct(h.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_hash_destroy(botan_hash_t hash)
   {
   return BOTAN_FFI_CHECKED_DELETE(hash);
   }

int botan_hash_output_length(botan_hash_t hash, size_t* out)
   {
   if(out == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { *out = h.output_length(); });
   }

int botan_hash_block_size(botan_hash_t hash, size_t* out)
   {
   if(out == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { *out = h.hash_block_size(); });
   }

int botan_hash_clear(botan_hash_t hash)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { h.clear(); });
   }

int botan_hash_update(botan_hash_t hash, const uint8_t* buf, size_t len)
   {
   if(len == 0)
      return 0;

   if(buf == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { h.update(buf, len); });
   }

int botan_hash_final(botan_hash_t hash, uint8_t out[])
   {
   if(out == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;
   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, { h.final(out); });
   }

int botan_hash_copy_state(botan_hash_t* dest, const botan_hash_t source)
   {
   return BOTAN_FFI_DO(Botan::HashFunction, source, src, {
      *dest = new botan_hash_struct(src.copy_state().release()); });
   }

int botan_hash_name(botan_hash_t hash, char* name, size_t* name_len)
   {
   if(name_len == nullptr)
      return BOTAN_FFI_ERROR_NULL_POINTER;

   return BOTAN_FFI_DO(Botan::HashFunction, hash, h, {
      return write_str_output(name, name_len, h.name()); });
   }

}
