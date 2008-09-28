/*************************************************
* CBC-MAC Source File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/cbc_mac.h>
#include <botan/lookup.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Update an CBC-MAC Calculation                  *
*************************************************/
void CBC_MAC::add_data(const byte input[], u32bit length)
   {
   u32bit xored = std::min(OUTPUT_LENGTH - position, length);
   xor_buf(state + position, input, xored);
   position += xored;

   if(position < OUTPUT_LENGTH)
      return;

   e->encrypt(state);
   input += xored;
   length -= xored;
   while(length >= OUTPUT_LENGTH)
      {
      xor_buf(state, input, OUTPUT_LENGTH);
      e->encrypt(state);
      input += OUTPUT_LENGTH;
      length -= OUTPUT_LENGTH;
      }

   xor_buf(state, input, length);
   position = length;
   }

/*************************************************
* Finalize an CBC-MAC Calculation                *
*************************************************/
void CBC_MAC::final_result(byte mac[])
   {
   if(position)
      e->encrypt(state);

   copy_mem(mac, state.begin(), state.size());
   state.clear();
   position = 0;
   }

/*************************************************
* CBC-MAC Key Schedule                           *
*************************************************/
void CBC_MAC::key(const byte key[], u32bit length)
   {
   e->set_key(key, length);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void CBC_MAC::clear() throw()
   {
   e->clear();
   state.clear();
   position = 0;
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string CBC_MAC::name() const
   {
   return "CBC-MAC(" + e->name() + ")";
   }

/*************************************************
* Return a clone of this object                  *
*************************************************/
MessageAuthenticationCode* CBC_MAC::clone() const
   {
   return new CBC_MAC(e->name());
   }

/*************************************************
* CBC-MAC Constructor                            *
*************************************************/
CBC_MAC::CBC_MAC(const std::string& cipher) :
   MessageAuthenticationCode(block_size_of(cipher),
                             min_keylength_of(cipher),
                             max_keylength_of(cipher),
                             keylength_multiple_of(cipher)),
   state(block_size_of(cipher))
   {
   e = get_block_cipher(cipher);
   position = 0;
   }

/*************************************************
* CBC-MAC Destructor                             *
*************************************************/
CBC_MAC::~CBC_MAC()
   {
   delete e;
   }

}
