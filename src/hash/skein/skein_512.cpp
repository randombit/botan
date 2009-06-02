/**
* The Skein-512 hash function
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/skein_512.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>
#include <algorithm>
#include <stdexcept>

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

void ubi_512(u64bit H[9], u64bit T[], const byte msg[], u64bit msg_len)
   {
   bool first = true;

   while(msg_len || first)
      {
      first = false;
      const u64bit to_proc = std::min<u64bit>(msg_len, 64);
      T[0] += to_proc;

      u64bit M[8] = { 0 };
      for(u32bit j = 0; j != to_proc / 8; ++j)
         M[j] = load_le<u64bit>(msg, j);

      if(to_proc % 8)
         {
         for(u32bit j = 0; j != to_proc % 8; ++j)
            M[to_proc/8] |= ((u64bit)msg[8*(to_proc/8)+j] << (8*j));
         }

      H[8] = H[0] ^ H[1] ^ H[2] ^ H[3] ^
             H[4] ^ H[5] ^ H[6] ^ H[7] ^ 0x5555555555555555;

      T[2] = T[0] ^ T[1];

      const u64bit K0 = H[0];
      const u64bit K1 = H[1];
      const u64bit K2 = H[2];
      const u64bit K3 = H[3];
      const u64bit K4 = H[4];
      const u64bit K5 = H[5];
      const u64bit K6 = H[6];
      const u64bit K7 = H[7];

      u64bit X0 = M[0] + K0;
      u64bit X1 = M[1] + K1;
      u64bit X2 = M[2] + K2;
      u64bit X3 = M[3] + K3;
      u64bit X4 = M[4] + K4;
      u64bit X5 = M[5] + K5 + T[0];
      u64bit X6 = M[6] + K6 + T[1];
      u64bit X7 = M[7] + K7;

#define SKEIN_ROUND(I1,I2,I3,I4,I5,I6,I7,I8,ROT1,ROT2,ROT3,ROT4)   \
      do {                                                         \
         X##I1 += X##I2; X##I2 = rotate_left(X##I2, ROT1) ^ X##I1; \
         X##I3 += X##I4; X##I4 = rotate_left(X##I4, ROT2) ^ X##I3; \
         X##I5 += X##I6; X##I6 = rotate_left(X##I6, ROT3) ^ X##I5; \
         X##I7 += X##I8; X##I8 = rotate_left(X##I8, ROT4) ^ X##I7; \
      } while(0);

#define SKEIN_INJECT_KEY(r)                     \
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

#define SKEIN_8_ROUNDS(R1,R2)                      \
      do {                                         \
         SKEIN_ROUND(0,1,2,3,4,5,6,7,38,30,50,53); \
         SKEIN_ROUND(2,1,4,7,6,5,0,3,48,20,43,31); \
         SKEIN_ROUND(4,1,6,3,0,5,2,7,34,14,15,27); \
         SKEIN_ROUND(6,1,0,7,2,5,4,3,26,12,58, 7); \
                                                   \
         SKEIN_INJECT_KEY(R1);                     \
                                                   \
         SKEIN_ROUND(0,1,2,3,4,5,6,7,33,49, 8,42); \
         SKEIN_ROUND(2,1,4,7,6,5,0,3,39,27,41,14); \
         SKEIN_ROUND(4,1,6,3,0,5,2,7,29,26,11, 9); \
         SKEIN_ROUND(6,1,0,7,2,5,4,3,33,51,39,35); \
                                                   \
         SKEIN_INJECT_KEY(R2);                     \
      } while(0);

      SKEIN_8_ROUNDS(1,2);
      SKEIN_8_ROUNDS(3,4);
      SKEIN_8_ROUNDS(5,6);
      SKEIN_8_ROUNDS(7,8);
      SKEIN_8_ROUNDS(9,10);
      SKEIN_8_ROUNDS(11,12);
      SKEIN_8_ROUNDS(13,14);
      SKEIN_8_ROUNDS(15,16);
      SKEIN_8_ROUNDS(17,18);

      // message feed forward
      H[0] = X0 ^ M[0];
      H[1] = X1 ^ M[1];
      H[2] = X2 ^ M[2];
      H[3] = X3 ^ M[3];
      H[4] = X4 ^ M[4];
      H[5] = X5 ^ M[5];
      H[6] = X6 ^ M[6];
      H[7] = X7 ^ M[7];

      T[1] &= ~((u64bit)1 << 62); // clear first flag if set

      msg_len -= to_proc;
      msg += to_proc;
      }
   }

void reset_tweak(u64bit T[3], type_code type, bool final)
   {
   T[0] = 0;
   T[1] = ((u64bit)type << 56) | ((u64bit)1 << 62) | ((u64bit)final << 63);
   }

void initial_block(u64bit H[9], u64bit T[3], u32bit output_bits)
   {
   clear_mem(H, 9);

   byte config_str[32] = { 0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0 };
   store_le(output_bits, config_str + 8);

   reset_tweak(T, SKEIN_CONFIG, true);
   ubi_512(H, T, config_str, sizeof(config_str));

#if 0
   if(personalization != "")
      {
      const byte* bits = reinterpret_cast<const byte*>(personalization.data());

      // FIXME: will be wrong if personalization > 64 bytes b/c final
      // bit is set for all blocks

      reset_tweak(T, SKEIN_PERSONALIZATION, true);
      ubi_512(H, T, bits, personalization.length());
      }
#endif

   reset_tweak(T, SKEIN_MSG, false);
   }

}

Skein_512::Skein_512(u32bit arg_output_bits) :
   HashFunction(arg_output_bits / 8, 64),
   output_bits(arg_output_bits), buf_pos(0)
   {
   if(output_bits == 0 || output_bits % 8 != 0)
      throw std::invalid_argument("Bad output bits size for Skein-512");

   initial_block(H, T, output_bits);
   }

std::string Skein_512::name() const
   {
   return "Skein-512(" + to_string(output_bits) + ")";
   }

void Skein_512::clear() throw()
   {
   H.clear();
   T.clear();
   buffer.clear();
   buf_pos = 0;
   }

void Skein_512::add_data(const byte input[], u32bit length)
   {
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

   const u32bit full_blocks = (length - 1) / 64;

   if(full_blocks)
      ubi_512(H, T, input, 64*full_blocks);

   length -= full_blocks * 64;

   buffer.copy(buf_pos, input + full_blocks * 64, length);
   buf_pos += length;
   }

void Skein_512::final_result(byte out[])
   {
   T[1] |= ((u64bit)1 << 63); // final block flag

   for(u32bit i = buf_pos; i != buffer.size(); ++i)
      buffer[i] = 0;

   ubi_512(H, T, &buffer[0], buf_pos);

   byte counter[8] = { 0 };

   u32bit out_bytes = output_bits / 8;

   SecureBuffer<u64bit, 9> H_out;

   while(out_bytes)
      {
      const u32bit to_proc = std::min<u32bit>(out_bytes, 64);

      H_out.copy(H.begin(), 8);

      reset_tweak(T, SKEIN_OUTPUT, true);
      ubi_512(H_out, T, counter, sizeof(counter));

      for(u32bit i = 0; i != to_proc; ++i)
         out[i] = get_byte(7-i%8, H_out[i/8]);

      out_bytes -= to_proc;
      out += to_proc;

      for(u32bit i = 0; i != sizeof(counter); ++i)
         if(++counter[i])
            break;
      }

   buf_pos = 0;
   initial_block(H, T, output_bits);
   }

}
