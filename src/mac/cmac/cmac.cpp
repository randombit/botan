/*
* CMAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cmac.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* Perform CMAC's multiplication in GF(2^n)
*/
secure_vector<byte> CMAC::poly_double(const secure_vector<byte>& in,
                                     byte polynomial)
   {
   const byte poly_xor = (in[0] & 0x80) ? polynomial : 0;

   secure_vector<byte> out = in;

   byte carry = 0;
   for(size_t i = out.size(); i != 0; --i)
      {
      byte temp = out[i-1];
      out[i-1] = (temp << 1) | carry;
      carry = (temp >> 7);
      }

   out[out.size()-1] ^= poly_xor;

   return out;
   }

/*
* Update an CMAC Calculation
*/
void CMAC::add_data(const byte input[], size_t length)
   {
   buffer_insert(buffer, position, input, length);
   if(position + length > output_length())
      {
      xor_buf(state, buffer, output_length());
      e->encrypt(state);
      input += (output_length() - position);
      length -= (output_length() - position);
      while(length > output_length())
         {
         xor_buf(state, input, output_length());
         e->encrypt(state);
         input += output_length();
         length -= output_length();
         }
      copy_mem(&buffer[0], input, length);
      position = 0;
      }
   position += length;
   }

/*
* Finalize an CMAC Calculation
*/
void CMAC::final_result(byte mac[])
   {
   xor_buf(state, buffer, position);

   if(position == output_length())
      {
      xor_buf(state, B, output_length());
      }
   else
      {
      state[position] ^= 0x80;
      xor_buf(state, P, output_length());
      }

   e->encrypt(state);

   for(size_t i = 0; i != output_length(); ++i)
      mac[i] = state[i];

   zeroise(state);
   zeroise(buffer);
   position = 0;
   }

/*
* CMAC Key Schedule
*/
void CMAC::key_schedule(const byte key[], size_t length)
   {
   clear();
   e->set_key(key, length);
   e->encrypt(B);
   B = poly_double(B, polynomial);
   P = poly_double(B, polynomial);
   }

/*
* Clear memory of sensitive data
*/
void CMAC::clear()
   {
   e->clear();
   zeroise(state);
   zeroise(buffer);
   zeroise(B);
   zeroise(P);
   position = 0;
   }

/*
* Return the name of this type
*/
std::string CMAC::name() const
   {
   return "CMAC(" + e->name() + ")";
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* CMAC::clone() const
   {
   return new CMAC(e->clone());
   }

/*
* CMAC Constructor
*/
CMAC::CMAC(BlockCipher* e_in) : e(e_in)
   {
   if(e->block_size() == 16)
      polynomial = 0x87;
   else if(e->block_size() == 8)
      polynomial = 0x1B;
   else
      throw Invalid_Argument("CMAC cannot use the cipher " + e->name());

   state.resize(output_length());
   buffer.resize(output_length());
   B.resize(output_length());
   P.resize(output_length());
   position = 0;
   }

/*
* CMAC Destructor
*/
CMAC::~CMAC()
   {
   delete e;
   }

}
