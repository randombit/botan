/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x919_mac.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* Update an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::add_data(const byte input[], u32bit length)
   {
   u32bit xored = std::min(8 - position, length);
   xor_buf(state + position, input, xored);
   position += xored;

   if(position < 8) return;

   e->encrypt(state);
   input += xored;
   length -= xored;
   while(length >= 8)
      {
      xor_buf(state, input, 8);
      e->encrypt(state);
      input += 8;
      length -= 8;
      }

   xor_buf(state, input, length);
   position = length;
   }

/*
* Finalize an ANSI X9.19 MAC Calculation
*/
void ANSI_X919_MAC::final_result(byte mac[])
   {
   if(position)
      e->encrypt(state);
   d->decrypt(state, mac);
   e->encrypt(mac);
   state.clear();
   position = 0;
   }

/*
* ANSI X9.19 MAC Key Schedule
*/
void ANSI_X919_MAC::key_schedule(const byte key[], u32bit length)
   {
   e->set_key(key, 8);
   if(length == 8) d->set_key(key, 8);
   else            d->set_key(key + 8, 8);
   }

/*
* Clear memory of sensitive data
*/
void ANSI_X919_MAC::clear() throw()
   {
   e->clear();
   d->clear();
   state.clear();
   position = 0;
   }

std::string ANSI_X919_MAC::name() const
   {
   return "X9.19-MAC";
   }

MessageAuthenticationCode* ANSI_X919_MAC::clone() const
   {
   return new ANSI_X919_MAC(e->clone());
   }

/*
* ANSI X9.19 MAC Constructor
*/
ANSI_X919_MAC::ANSI_X919_MAC(BlockCipher* e_in) :
   MessageAuthenticationCode(e_in->BLOCK_SIZE,
                             e_in->MINIMUM_KEYLENGTH,
                             2*e_in->MAXIMUM_KEYLENGTH,
                             2*e_in->KEYLENGTH_MULTIPLE),
   e(e_in), d(e->clone()), position(0)
   {
   if(e->name() != "DES")
      throw Invalid_Argument("ANSI X9.19 MAC only supports DES");
   }

/*
* ANSI X9.19 MAC Destructor
le*/
ANSI_X919_MAC::~ANSI_X919_MAC()
   {
   delete e;
   delete d;
   }

}
