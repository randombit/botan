/*
* ARC4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/arc4.h>
#include <botan/internal/xor_buf.h>
#include <botan/parsing.h>

namespace Botan {

/*
* Combine cipher stream with message
*/
void ARC4::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, &buffer[position], buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      generate();
      }
   xor_buf(out, in, &buffer[position], length);
   position += length;
   }

/*
* Generate cipher stream
*/
void ARC4::generate()
   {
   byte SX, SY;
   for(size_t i = 0; i != buffer.size(); i += 4)
      {
      SX = state[X+1]; Y = (Y + SX) % 256; SY = state[Y];
      state[X+1] = SY; state[Y] = SX;
      buffer[i] = state[(SX + SY) % 256];

      SX = state[X+2]; Y = (Y + SX) % 256; SY = state[Y];
      state[X+2] = SY; state[Y] = SX;
      buffer[i+1] = state[(SX + SY) % 256];

      SX = state[X+3]; Y = (Y + SX) % 256; SY = state[Y];
      state[X+3] = SY; state[Y] = SX;
      buffer[i+2] = state[(SX + SY) % 256];

      X = (X + 4) % 256;
      SX = state[X]; Y = (Y + SX) % 256; SY = state[Y];
      state[X] = SY; state[Y] = SX;
      buffer[i+3] = state[(SX + SY) % 256];
      }
   position = 0;
   }

/*
* ARC4 Key Schedule
*/
void ARC4::key_schedule(const byte key[], size_t length)
   {
   clear();

   for(size_t i = 0; i != 256; ++i)
      state[i] = static_cast<byte>(i);

   for(size_t i = 0, state_index = 0; i != 256; ++i)
      {
      state_index = (state_index + key[i % length] + state[i]) % 256;
      std::swap(state[i], state[state_index]);
      }

   for(size_t i = 0; i <= SKIP; i += buffer.size())
      generate();

   position += (SKIP % buffer.size());
   }

/*
* Return the name of this type
*/
std::string ARC4::name() const
   {
   if(SKIP == 0)   return "ARC4";
   if(SKIP == 256) return "MARK-4";
   else            return "RC4_skip(" + to_string(SKIP) + ")";
   }

/*
* Clear memory of sensitive data
*/
void ARC4::clear()
   {
   zeroise(state);
   zeroise(buffer);
   position = X = Y = 0;
   }

/*
* ARC4 Constructor
*/
ARC4::ARC4(size_t s) : SKIP(s),
                       state(256),
                       buffer(DEFAULT_BUFFERSIZE)
   {
   clear();
   }

}
