/*
* CBC-MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cbc_mac.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* Update an CBC-MAC Calculation
*/
void CBC_MAC::add_data(const byte input[], size_t length)
   {
   size_t xored = std::min(output_length() - position, length);
   xor_buf(&state[position], input, xored);
   position += xored;

   if(position < output_length())
      return;

   e->encrypt(state);
   input += xored;
   length -= xored;
   while(length >= output_length())
      {
      xor_buf(state, input, output_length());
      e->encrypt(state);
      input += output_length();
      length -= output_length();
      }

   xor_buf(state, input, length);
   position = length;
   }

/*
* Finalize an CBC-MAC Calculation
*/
void CBC_MAC::final_result(byte mac[])
   {
   if(position)
      e->encrypt(state);

   copy_mem(mac, &state[0], state.size());
   zeroise(state);
   position = 0;
   }

/*
* CBC-MAC Key Schedule
*/
void CBC_MAC::key_schedule(const byte key[], size_t length)
   {
   e->set_key(key, length);
   }

/*
* Clear memory of sensitive data
*/
void CBC_MAC::clear()
   {
   e->clear();
   zeroise(state);
   position = 0;
   }

/*
* Return the name of this type
*/
std::string CBC_MAC::name() const
   {
   return "CBC-MAC(" + e->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* CBC_MAC::clone() const
   {
   return new CBC_MAC(e->clone());
   }

/*
* CBC-MAC Constructor
*/
CBC_MAC::CBC_MAC(BlockCipher* e_in) :
   e(e_in), state(e->block_size())
   {
   position = 0;
   }

/*
* CBC-MAC Destructor
*/
CBC_MAC::~CBC_MAC()
   {
   delete e;
   }

}
