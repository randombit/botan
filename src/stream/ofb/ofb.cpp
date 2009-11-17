/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ofb.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* OFB Constructor
*/
OFB::OFB(BlockCipher* ciph) :
   StreamCipher(ciph->MINIMUM_KEYLENGTH,
                ciph->MAXIMUM_KEYLENGTH,
                ciph->KEYLENGTH_MULTIPLE),
   permutation(ciph)
   {
   position = 0;
   buffer.resize(permutation->BLOCK_SIZE);
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
   buffer.clear();
   position = 0;
   }

/*
* Set the key
*/
void OFB::key_schedule(const byte key[], u32bit key_len)
   {
   permutation->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(0, 0);
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
void OFB::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer.begin() + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      permutation->encrypt(buffer);
      position = 0;
      }
   xor_buf(out, in, buffer.begin() + position, length);
   position += length;
   }

/*
* Set CTR-BE IV
*/
void OFB::set_iv(const byte iv[], u32bit iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   buffer.clear();
   buffer.copy(0, iv, iv_len);

   permutation->encrypt(buffer);
   position = 0;
   }

}
