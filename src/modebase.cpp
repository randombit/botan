/*************************************************
* Block Cipher Mode Source File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/modebase.h>
#include <botan/lookup.h>

namespace Botan {

/*************************************************
* Block Cipher Mode Constructor                  *
*************************************************/
BlockCipherMode::BlockCipherMode(const std::string& cipher_name,
                                 const std::string& cipher_mode_name,
                                 u32bit iv_size, u32bit iv_meth,
                                 u32bit buf_mult) :
   BLOCK_SIZE(block_size_of(cipher_name)), BUFFER_SIZE(buf_mult * BLOCK_SIZE),
   IV_METHOD(iv_meth), mode_name(cipher_mode_name)
   {
   base_ptr = cipher = get_block_cipher(cipher_name);
   buffer.create(BUFFER_SIZE);
   state.create(iv_size);
   position = 0;
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string BlockCipherMode::name() const
   {
   return (cipher->name() + "/" + mode_name);
   }

/*************************************************
* Set the IV                                     *
*************************************************/
void BlockCipherMode::set_iv(const InitializationVector& new_iv)
   {
   if(new_iv.length() != state.size())
      throw Invalid_IV_Length(name(), new_iv.length());

   state = new_iv.bits_of();
   buffer.clear();
   position = 0;

   if(IV_METHOD == 1)
      cipher->encrypt(state, buffer);
   else if(IV_METHOD == 2)
      cipher->encrypt(state);
   }

}
