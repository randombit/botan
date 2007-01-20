/*************************************************
* AEP Interface Source File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/eng_aep.h>
#include <botan/parsing.h>
#include <botan/util.h>
#include <botan/mutex.h>
#include <botan/aep_conn.h>
#include <botan/hw_aep.h>
#include <botan/es_aep.h>

namespace Botan {

namespace {

/*************************************************
* AEP Exception                                  *
*************************************************/
class AEP_Exception : public Exception
   {
   public:
      AEP_Exception(const std::string func, u32bit retval) :
         Exception(func + " failed; returned " + to_string(retval)) {}
   };

/*************************************************
* Return the size in bytes of this BigInt        *
*************************************************/
u32bit get_bigint_size(void* bigint_ptr, u32bit* bytes)
   {
   const BigInt* bigint = static_cast<BigInt*>(bigint_ptr);
   const u32bit actual_bytes = bigint->bytes();
   *bytes = round_up(actual_bytes, 4);
   return 0;
   }

/*************************************************
* Store a BigInt into AEP format                 *
*************************************************/
u32bit store_bigint(void* bigint_ptr, u32bit output_size, byte* output)
   {
   const BigInt* bigint = static_cast<BigInt*>(bigint_ptr);

   const u32bit leading_zeros = round_up(bigint->bytes(), 4) - bigint->bytes();

   clear_mem(output, output_size);
   bigint->binary_encode(output + leading_zeros);
   for(u32bit j = 0; j != output_size / 2; j++)
      std::swap(output[j], output[output_size-j-1]);

   return 0;
   }

/*************************************************
* Read a BigInt from the AEP format              *
*************************************************/
u32bit create_bigint(void* bigint_ptr, u32bit input_size, byte* input)
   {
   BigInt* bigint = static_cast<BigInt*>(bigint_ptr);

   for(u32bit j = 0; j != input_size / 2; j++)
      std::swap(input[j], input[input_size-j-1]);
   bigint->binary_decode(input, input_size);

   return 0;
   }

}

/*************************************************
* AEP Modular Exponentiation Operation           *
*************************************************/
BigInt AEP_Engine::pow_mod(const BigInt& i, const BigInt& x, const BigInt& m)
   {
   BigInt output;

   AEP_Connection conn;
   u32bit retval = AEP::AEP_ModExp(conn, &i, &x, &m, &output, 0);

   if(retval != 0)
      throw AEP_Exception("AEP_ModExp", retval);

   return output;
   }

/*************************************************
* AEP Modular Exponentiation with CRT Operation  *
*************************************************/
BigInt AEP_Engine::pow_mod_crt(const BigInt& i, const BigInt&,
                               const BigInt& p, const BigInt& q,
                               const BigInt& d1, const BigInt& d2,
                               const BigInt& c)
   {
   BigInt output;

   AEP_Connection conn;
   u32bit retval = AEP::AEP_ModExpCrt(conn, &i, &p, &q, &d1, &d2, &c,
                                      &output, 0);

   if(retval != 0)
      throw AEP_Exception("AEP_ModExpCrt", retval);
   return output;
   }

/*************************************************
* AEP RNG Operation                              *
*************************************************/
u32bit AEP_Engine::get_entropy(byte output[], u32bit length) throw()
   {
   if(length > 256)
      length = 256;

   try {
      AEP_Connection conn;
      u32bit retval = AEP::AEP_GenRandom(conn, length, 1, output, 0);

      if(retval != 0)
         return 0;
      return length;
   }
   catch(...)
      {
      return 0;
      }
   }

/*************************************************
* AEP usability check                            *
*************************************************/
bool AEP_Engine::ok_to_use(const BigInt& x) throw()
   {
   if(daemon_is_up && (x.bits() <= AEP::MAX_MODULO_BITS))
      return true;
   return false;
   }

/*************************************************
* AEP daemon status flag                         *
*************************************************/
bool AEP_Engine::daemon_is_up = false;

/*************************************************
* AEP_Engine Constructor                         *
*************************************************/
AEP_Engine::AEP_Engine()
   {
   daemon_is_up = false;

   try {
      u32bit retval = AEP::AEP_Initialize(0);

      if(retval != 0 && retval != AEP::ALREADY_INIT)
         throw AEP_Exception("AEP_Initialize", retval);

      if(retval == 0)
         {
         retval = AEP::AEP_SetBNCallBacks(get_bigint_size, store_bigint,
                                          create_bigint);
         if(retval != 0)
            throw AEP_Exception("AEP_SetBNCallBacks", retval);

         AEP_Connection conn;
         daemon_is_up = true;
         }
   }
   catch(AEP_Exception&) {}
   }

/*************************************************
* AEP_Engine Destructor                          *
*************************************************/
AEP_Engine::~AEP_Engine()
   {
   AEP_Connection::close_all_connections();
   u32bit retval = AEP::AEP_Finalize();
   if(retval != 0)
      throw AEP_Exception("AEP_Finalize", retval);
   }

/*************************************************
* Gather Entropy from AEP Hardware RNG           *
*************************************************/
u32bit AEP_EntropySource::slow_poll(byte output[], u32bit length)
   {
   return AEP_Engine::get_entropy(output, length);
   }

}
