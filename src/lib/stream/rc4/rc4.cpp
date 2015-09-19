/*
* RC4
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rc4.h>

namespace Botan {

RC4* RC4::make(const Spec& spec)
   {
   if(spec.algo_name() == "RC4")
      return new RC4(spec.arg_as_integer(0, 0));
   if(spec.algo_name() == "RC4_drop")
      return new RC4(768);
   return nullptr;
   }

/*
* Combine cipher stream with message
*/
void RC4::cipher(const byte in[], byte out[], size_t length)
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
void RC4::generate()
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
* RC4 Key Schedule
*/
void RC4::key_schedule(const byte key[], size_t length)
   {
   state.resize(256);
   buffer.resize(256);

   position = X = Y = 0;

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
std::string RC4::name() const
   {
   if(SKIP == 0)   return "RC4";
   if(SKIP == 256) return "MARK-4";
   else            return "RC4_skip(" + std::to_string(SKIP) + ")";
   }

/*
* Clear memory of sensitive data
*/
void RC4::clear()
   {
   zap(state);
   zap(buffer);
   position = X = Y = 0;
   }

/*
* RC4 Constructor
*/
RC4::RC4(size_t s) : SKIP(s), X(0), Y(0) {}

}
