/*
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   #include <botan/rfc3394.h>
#endif

extern "C" {

using namespace Botan_FFI;

int botan_key_wrap3394(const uint8_t key[], size_t key_len,
                       const uint8_t kek[], size_t kek_len,
                       uint8_t wrapped_key[], size_t* wrapped_key_len)
   {
#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::SymmetricKey kek_sym(kek, kek_len);
      const Botan::secure_vector<uint8_t> key_pt(key, key + key_len);
      const Botan::secure_vector<uint8_t> key_ct = Botan::rfc3394_keywrap(key_pt, kek_sym);
      return write_vec_output(wrapped_key, wrapped_key_len, key_ct);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_key_unwrap3394(const uint8_t wrapped_key[], size_t wrapped_key_len,
                         const uint8_t kek[], size_t kek_len,
                         uint8_t key[], size_t* key_len)
   {
#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const Botan::SymmetricKey kek_sym(kek, kek_len);
      const Botan::secure_vector<uint8_t> key_ct(wrapped_key, wrapped_key + wrapped_key_len);
      const Botan::secure_vector<uint8_t> key_pt = Botan::rfc3394_keyunwrap(key_ct, kek_sym);
      return write_vec_output(key, key_len, key_pt);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

}
