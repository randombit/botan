/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/mac.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_mac_struct, Botan::MessageAuthenticationCode, 0xA06E8FC1);

int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags)
   {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(!mac || !mac_name || flags != 0)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      std::unique_ptr<Botan::MessageAuthenticationCode> m =
         Botan::MessageAuthenticationCode::create(mac_name);

      if(m == nullptr)
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

      *mac = new botan_mac_struct(m.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_mac_destroy(botan_mac_t mac)
   {
   return BOTAN_FFI_CHECKED_DELETE(mac);
   }

int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.set_key(key, key_len); });
   }

int botan_mac_output_length(botan_mac_t mac, size_t* out)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { *out = m.output_length(); });
   }

int botan_mac_clear(botan_mac_t mac)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.clear(); });
   }

int botan_mac_update(botan_mac_t mac, const uint8_t* buf, size_t len)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.update(buf, len); });
   }

int botan_mac_final(botan_mac_t mac, uint8_t out[])
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, { m.final(out); });
   }

int botan_mac_name(botan_mac_t mac, char* name, size_t* name_len)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, {
      return write_str_output(name, name_len, m.name()); });
   }

int botan_mac_get_keyspec(botan_mac_t mac,
                          size_t* out_minimum_keylength,
                          size_t* out_maximum_keylength,
                          size_t* out_keylength_modulo)
   {
   return BOTAN_FFI_DO(Botan::MessageAuthenticationCode, mac, m, {
      if(out_minimum_keylength)
         *out_minimum_keylength = m.minimum_keylength();
      if(out_maximum_keylength)
         *out_maximum_keylength = m.maximum_keylength();
      if(out_keylength_modulo)
         *out_keylength_modulo = m.key_spec().keylength_multiple();
      });
   }

}
