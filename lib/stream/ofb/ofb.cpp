/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ofb.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* OFB Constructor
*/
OFB::OFB(BlockCipher* ciph) : permutation(ciph)
   {
   position = 0;
   buffer.resize(permutation->block_size());
   }

/*
* OFB Destructor
*/
OFB::~OFB()
   {
   delete permutation;
   }

/*
* Zeroize
*/
void OFB::clear()
   {
   permutation->clear();
   zeroise(buffer);
   position = 0;
   }

/*
* Set the key
*/
void OFB::key_schedule(const byte key[], size_t key_len)
   {
   permutation->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

/*
* Return the name of this type
*/
std::string OFB::name() const
   {
   return ("OFB(" + permutation->name() + ")");
   }

/*
* CTR-BE Encryption/Decryption
*/
void OFB::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, &buffer[position], buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      permutation->encrypt(buffer);
      position = 0;
      }
   xor_buf(out, in, &buffer[position], length);
   position += length;
   }

/*
* Set CTR-BE IV
*/
void OFB::set_iv(const byte iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   zeroise(buffer);
   buffer_insert(buffer, 0, iv, iv_len);

   permutation->encrypt(buffer);
   position = 0;
   }

}
