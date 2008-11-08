/**
* BufferedComputation
* (C) 1999-2007 Jack Lloyd
*/

#include <botan/buf_comp.h>

namespace Botan {

/*************************************************
* BufferedComputation Constructor                *
*************************************************/
BufferedComputation::BufferedComputation(u32bit olen) : OUTPUT_LENGTH(olen)
   {
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const byte in[], u32bit n)
   {
   add_data(in, n);
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const MemoryRegion<byte>& in)
   {
   add_data(in, in.size());
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const std::string& str)
   {
   update(reinterpret_cast<const byte*>(str.data()), str.size());
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(byte in)
   {
   update(&in, 1);
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::final()
   {
   SecureVector<byte> output(OUTPUT_LENGTH);
   final_result(output);
   return output;
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const byte in[], u32bit len)
   {
   update(in, len);
   return final();
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const MemoryRegion<byte>& in)
   {
   update(in, in.size());
   return final();
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const std::string& in)
   {
   update(in);
   return final();
   }

}
