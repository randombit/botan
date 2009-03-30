/*
* ARC4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/arc4.h>
#include <botan/xor_buf.h>
#include <botan/parsing.h>

namespace Botan {

/*
* Combine cipher stream with message
*/
void ARC4::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer.begin() + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      generate();
      }
   xor_buf(out, in, buffer.begin() + position, length);
   position += length;
   }

/*
* Generate cipher stream
*/
void ARC4::generate()
   {
   u32bit SX, SY;
   for(u32bit j = 0; j != buffer.size(); j += 4)
      {
      SX = state[X+1]; Y = (Y + SX) % 256; SY = state[Y];
      state[X+1] = SY; state[Y] = SX;
      buffer[j] = state[(SX + SY) % 256];

      SX = state[X+2]; Y = (Y + SX) % 256; SY = state[Y];
      state[X+2] = SY; state[Y] = SX;
      buffer[j+1] = state[(SX + SY) % 256];

      SX = state[X+3]; Y = (Y + SX) % 256; SY = state[Y];
      state[X+3] = SY; state[Y] = SX;
      buffer[j+2] = state[(SX + SY) % 256];

      X = (X + 4) % 256;
      SX = state[X]; Y = (Y + SX) % 256; SY = state[Y];
      state[X] = SY; state[Y] = SX;
      buffer[j+3] = state[(SX + SY) % 256];
      }
   position = 0;
   }

/*
* ARC4 Key Schedule
*/
void ARC4::key_schedule(const byte key[], u32bit length)
   {
   clear();
   for(u32bit j = 0; j != 256; ++j)
      state[j] = j;
   for(u32bit j = 0, state_index = 0; j != 256; ++j)
      {
      state_index = (state_index + key[j % length] + state[j]) % 256;
      std::swap(state[j], state[state_index]);
      }
   for(u32bit j = 0; j <= SKIP; j += buffer.size())
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
void ARC4::clear() throw()
   {
   state.clear();
   buffer.clear();
   position = X = Y = 0;
   }

/*
* ARC4 Constructor
*/
ARC4::ARC4(u32bit s) : StreamCipher(1, 256), SKIP(s)
   {
   clear();
   }

}
