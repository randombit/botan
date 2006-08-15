/*************************************************
* Serpent Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/serpent.h>
#include <botan/bit_ops.h>

namespace Botan {

extern "C" void serpent_encrypt(const byte[16], byte[16], const u32bit[132]);
extern "C" void serpent_decrypt(const byte[16], byte[16], const u32bit[132]);
extern "C" void serpent_key_schedule(u32bit[140]);

/*************************************************
* Serpent Encryption                             *
*************************************************/
void Serpent::enc(const byte in[], byte out[]) const
   {
   serpent_encrypt(in, out, round_key);
   }

/*************************************************
* Serpent Decryption                             *
*************************************************/
void Serpent::dec(const byte in[], byte out[]) const
   {
   serpent_decrypt(in, out, round_key);
   }

/*************************************************
* Serpent Key Schedule                           *
*************************************************/
void Serpent::key(const byte key[], u32bit length)
   {
   const u32bit PHI = 0x9E3779B9;

   SecureBuffer<u32bit, 140> W;
   for(u32bit j = 0; j != length / 4; ++j)
      W[j] = make_u32bit(key[4*j+3], key[4*j+2], key[4*j+1], key[4*j]);
   W[length / 4] |= u32bit(1) << ((length%4)*8);

   serpent_key_schedule(W);

   round_key.copy(W + 8, 132);
   }

}
