/*
* The Skein-512 hash function
* (C) 2009-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/skein_512.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <botan/rotate.h>
#include <algorithm>

namespace Botan {

namespace {

enum type_code {
   SKEIN_KEY = 0,
   SKEIN_CONFIG = 4,
   SKEIN_PERSONALIZATION = 8,
   SKEIN_PUBLIC_KEY = 12,
   SKEIN_KEY_IDENTIFIER = 16,
   SKEIN_NONCE = 20,
   SKEIN_MSG = 48,
   SKEIN_OUTPUT = 63
};

void ubi_512(MemoryRegion<u64bit>& H,
             MemoryRegion<u64bit>& T,
             const byte msg[], size_t msg_len)
   {
   do
      {
      const size_t to_proc = std::min<size_t>(msg_len, 64);
      T[0] += to_proc;

      u64bit M[8] = { 0 };

      load_le(M, msg, to_proc / 8);

      if(to_proc % 8)
         {
         for(size_t j = 0; j != to_proc % 8; ++j)
           M[to_proc/8] |= static_cast<u64bit>(msg[8*(to_proc/8)+j]) << (8*j);
         }

      H[8] = H[0] ^ H[1] ^ H[2] ^ H[3] ^
             H[4] ^ H[5] ^ H[6] ^ H[7] ^ 0x1BD11BDAA9FC1A22;

      T[2] = T[0] ^ T[1];

      u64bit X0 = M[0] + H[0];
      u64bit X1 = M[1] + H[1];
      u64bit X2 = M[2] + H[2];
      u64bit X3 = M[3] + H[3];
      u64bit X4 = M[4] + H[4];
      u64bit X5 = M[5] + H[5] + T[0];
      u64bit X6 = M[6] + H[6] + T[1];
      u64bit X7 = M[7] + H[7];

#define THREEFISH_ROUND(I1,I2,I3,I4,I5,I6,I7,I8,ROT1,ROT2,ROT3,ROT4)   \
      do {                                                             \
         X##I1 += X##I2; X##I2 = rotate_left(X##I2, ROT1) ^ X##I1;     \
         X##I3 += X##I4; X##I4 = rotate_left(X##I4, ROT2) ^ X##I3;     \
         X##I5 += X##I6; X##I6 = rotate_left(X##I6, ROT3) ^ X##I5;     \
         X##I7 += X##I8; X##I8 = rotate_left(X##I8, ROT4) ^ X##I7;     \
      } while(0);

#define THREEFISH_INJECT_KEY(r)                 \
      do {                                      \
         X0 += H[(r  ) % 9];                    \
         X1 += H[(r+1) % 9];                    \
         X2 += H[(r+2) % 9];                    \
         X3 += H[(r+3) % 9];                    \
         X4 += H[(r+4) % 9];                    \
         X5 += H[(r+5) % 9] + T[(r  ) % 3];     \
         X6 += H[(r+6) % 9] + T[(r+1) % 3];     \
         X7 += H[(r+7) % 9] + (r);              \
      } while(0);

#define THREEFISH_8_ROUNDS(R1,R2)                         \
      do {                                                \
         THREEFISH_ROUND(0,1,2,3,4,5,6,7, 46,36,19,37);   \
         THREEFISH_ROUND(2,1,4,7,6,5,0,3, 33,27,14,42);   \
         THREEFISH_ROUND(4,1,6,3,0,5,2,7, 17,49,36,39);   \
         THREEFISH_ROUND(6,1,0,7,2,5,4,3, 44, 9,54,56);   \
                                                          \
         THREEFISH_INJECT_KEY(R1);                        \
                                                          \
         THREEFISH_ROUND(0,1,2,3,4,5,6,7, 39,30,34,24);   \
         THREEFISH_ROUND(2,1,4,7,6,5,0,3, 13,50,10,17);   \
         THREEFISH_ROUND(4,1,6,3,0,5,2,7, 25,29,39,43);   \
         THREEFISH_ROUND(6,1,0,7,2,5,4,3,  8,35,56,22);   \
                                                          \
         THREEFISH_INJECT_KEY(R2);                        \
      } while(0);

      THREEFISH_8_ROUNDS(1,2);
      THREEFISH_8_ROUNDS(3,4);
      THREEFISH_8_ROUNDS(5,6);
      THREEFISH_8_ROUNDS(7,8);
      THREEFISH_8_ROUNDS(9,10);
      THREEFISH_8_ROUNDS(11,12);
      THREEFISH_8_ROUNDS(13,14);
      THREEFISH_8_ROUNDS(15,16);
      THREEFISH_8_ROUNDS(17,18);

      // message feed forward
      H[0] = X0 ^ M[0];
      H[1] = X1 ^ M[1];
      H[2] = X2 ^ M[2];
      H[3] = X3 ^ M[3];
      H[4] = X4 ^ M[4];
      H[5] = X5 ^ M[5];
      H[6] = X6 ^ M[6];
      H[7] = X7 ^ M[7];

      // clear first flag if set
      T[1] &= ~(static_cast<u64bit>(1) << 62);

      msg_len -= to_proc;
      msg += to_proc;
      } while(msg_len);
   }

void reset_tweak(MemoryRegion<u64bit>& T,
                 type_code type, bool final)
   {
   T[0] = 0;

   T[1] = (static_cast<u64bit>(type) << 56) |
          (static_cast<u64bit>(1) << 62) |
          (static_cast<u64bit>(final) << 63);
   }

void initial_block(MemoryRegion<u64bit>& H,
                   MemoryRegion<u64bit>& T,
                   size_t output_bits,
                   const std::string& personalization)
   {
   zeroise(H);

   // ASCII("SHA3") followed by version (0x0001) code
   byte config_str[32] = { 0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0 };
   store_le(u32bit(output_bits), config_str + 8);

   reset_tweak(T, SKEIN_CONFIG, true);
   ubi_512(H, T, config_str, sizeof(config_str));

   if(personalization != "")
      {
      /*
        This is a limitation of this implementation, and not of the
        algorithm specification. Could be fixed relatively easily, but
        doesn't seem worth the trouble.
      */
      if(personalization.length() > 64)
         throw Invalid_Argument("Skein personalization must be <= 64 bytes");

      const byte* bits = reinterpret_cast<const byte*>(personalization.data());

      reset_tweak(T, SKEIN_PERSONALIZATION, true);
      ubi_512(H, T, bits, personalization.length());
      }

   reset_tweak(T, SKEIN_MSG, false);
   }

}

Skein_512::Skein_512(size_t arg_output_bits,
                     const std::string& arg_personalization) :
   personalization(arg_personalization),
   output_bits(arg_output_bits),
   H(9), T(3), buffer(64), buf_pos(0)
   {
   if(output_bits == 0 || output_bits % 8 != 0 || output_bits > 64*1024)
      throw Invalid_Argument("Bad output bits size for Skein-512");

   initial_block(H, T, output_bits, personalization);
   }

std::string Skein_512::name() const
   {
   if(personalization != "")
      return "Skein-512(" + to_string(output_bits) + "," + personalization + ")";
   return "Skein-512(" + to_string(output_bits) + ")";
   }

HashFunction* Skein_512::clone() const
   {
   return new Skein_512(output_bits, personalization);
   }

void Skein_512::clear()
   {
   zeroise(H);
   zeroise(T);
   zeroise(buffer);
   buf_pos = 0;
   }

void Skein_512::add_data(const byte input[], size_t length)
   {
   if(length == 0)
      return;

   if(buf_pos)
      {
      buffer.copy(buf_pos, input, length);
      if(buf_pos + length > 64)
         {
         ubi_512(H, T, &buffer[0], buffer.size());

         input += (64 - buf_pos);
         length -= (64 - buf_pos);
         buf_pos = 0;
         }
      }

   const size_t full_blocks = (length - 1) / 64;

   if(full_blocks)
      ubi_512(H, T, input, 64*full_blocks);

   length -= full_blocks * 64;

   buffer.copy(buf_pos, input + full_blocks * 64, length);
   buf_pos += length;
   }

void Skein_512::final_result(byte out[])
   {
   T[1] |= (static_cast<u64bit>(1) << 63); // final block flag

   for(size_t i = buf_pos; i != buffer.size(); ++i)
      buffer[i] = 0;

   ubi_512(H, T, &buffer[0], buf_pos);

   byte counter[8] = { 0 };

   size_t out_bytes = output_bits / 8;

   SecureVector<u64bit> H_out(9);

   while(out_bytes)
      {
      const size_t to_proc = std::min<size_t>(out_bytes, 64);

      H_out.copy(&H[0], 8);

      reset_tweak(T, SKEIN_OUTPUT, true);
      ubi_512(H_out, T, counter, sizeof(counter));

      for(size_t i = 0; i != to_proc; ++i)
         out[i] = get_byte(7-i%8, H_out[i/8]);

      out_bytes -= to_proc;
      out += to_proc;

      for(size_t i = 0; i != sizeof(counter); ++i)
         if(++counter[i])
            break;
      }

   buf_pos = 0;
   initial_block(H, T, output_bits, personalization);
   }

}
