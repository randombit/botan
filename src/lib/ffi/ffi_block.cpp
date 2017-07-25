/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/block_cipher.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_block_cipher_struct, Botan::BlockCipher, 0x64C29716);

int botan_block_cipher_init(botan_block_cipher_t* bc, const char* bc_name)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() {
      if(bc == nullptr || bc_name == nullptr || *bc_name == 0)
         return BOTAN_FFI_ERROR_NULL_POINTER;

      *bc = nullptr;

      std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create(bc_name));
      if(cipher == nullptr)
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

      *bc = new botan_block_cipher_struct(cipher.release());
      return BOTAN_FFI_SUCCESS;
      });
   }

/**
* Destroy a block cipher object
*/
int botan_block_cipher_destroy(botan_block_cipher_t bc)
   {
   return BOTAN_FFI_CHECKED_DELETE(bc);
   }

int botan_block_cipher_clear(botan_block_cipher_t bc)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.clear(); });
   }

/**
* Set the key for a block cipher instance
*/
int botan_block_cipher_set_key(botan_block_cipher_t bc,
                               const uint8_t key[], size_t len)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.set_key(key, len); });
   }

/**
* Return the positive block size of this block cipher, or negative to
* indicate an error
*/
int botan_block_cipher_block_size(botan_block_cipher_t bc)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { return b.block_size(); });
   }

int botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc,
                                      const uint8_t in[],
                                      uint8_t out[],
                                      size_t blocks)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.encrypt_n(in, out, blocks); });
   }

int botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc,
                                      const uint8_t in[],
                                      uint8_t out[],
                                      size_t blocks)
   {
   return BOTAN_FFI_DO(Botan::BlockCipher, bc, b, { b.decrypt_n(in, out, blocks); });
   }

}
