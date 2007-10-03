/*************************************************
* Discrete Logarithm Parameters Source File      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/dl_group.h>
#include <botan/config.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pipe.h>
#include <botan/util.h>
#include <botan/pem.h>

namespace Botan {

/*************************************************
* DL_Group Constructor                           *
*************************************************/
DL_Group::DL_Group()
   {
   initialized = false;
   }

/*************************************************
* DL_Group Constructor                           *
*************************************************/
DL_Group::DL_Group(const std::string& type)
   {
   std::string grp_contents = global_config().get("dl", type);

   if(grp_contents == "")
      throw Invalid_Argument("DL_Group: Unknown group " + type);

   DataSource_Memory pem(grp_contents);
   PEM_decode(pem);
   }

/*************************************************
* DL_Group Constructor                           *
*************************************************/
DL_Group::DL_Group(PrimeType type, u32bit pbits, u32bit qbits)
   {
   if(pbits < 512)
      throw Invalid_Argument("DL_Group: prime size " + to_string(pbits) +
                             " is too small");

   if(type == Strong)
      {
      p = random_safe_prime(pbits);
      q = (p - 1) / 2;
      g = 2;
      }
   else if(type == Prime_Subgroup || type == DSA_Kosherizer)
      {
      if(type == Prime_Subgroup)
         {
         if(!qbits)
            qbits = 2 * dl_work_factor(pbits);

         q = random_prime(qbits);
         BigInt X;
         while(p.bits() != pbits || !is_prime(p))
            {
            X = random_integer(pbits);
            p = X - (X % (2*q) - 1);
            }
         }
      else
         {
         qbits = qbits ? qbits : ((pbits == 1024) ? 160 : 256);
         generate_dsa_primes(p, q, pbits, qbits);
         }

      g = make_dsa_generator(p, q);
      }

   initialized = true;
   }

/*************************************************
* DL_Group Constructor                           *
*************************************************/
DL_Group::DL_Group(const MemoryRegion<byte>& seed, u32bit pbits, u32bit qbits)
   {
   if(!generate_dsa_primes(p, q, pbits, qbits, seed))
      throw Invalid_Argument("DL_Group: The seed/counter given does not "
                             "generate a DSA group");

   g = make_dsa_generator(p, q);

   initialized = true;
   }

/*************************************************
* DL_Group Constructor                           *
*************************************************/
DL_Group::DL_Group(const BigInt& p1, const BigInt& g1)
   {
   initialize(p1, 0, g1);
   }

/*************************************************
* DL_Group Constructor                           *
*************************************************/
DL_Group::DL_Group(const BigInt& p1, const BigInt& q1, const BigInt& g1)
   {
   initialize(p1, q1, g1);
   }

/*************************************************
* DL_Group Initializer                           *
*************************************************/
void DL_Group::initialize(const BigInt& p1, const BigInt& q1, const BigInt& g1)
   {
   if(p1 < 3)
      throw Invalid_Argument("DL_Group: Prime invalid");
   if(g1 < 2 || g1 >= p1)
      throw Invalid_Argument("DL_Group: Generator invalid");
   if(q1 < 0 || q1 >= p1)
      throw Invalid_Argument("DL_Group: Subgroup invalid");

   p = p1;
   g = g1;
   q = q1;

   if(q == 0 && check_prime((p - 1) / 2))
      q = (p - 1) / 2;

   initialized = true;
   }

/*************************************************
* Verify that the group has been set             *
*************************************************/
void DL_Group::init_check() const
   {
   if(!initialized)
      throw Invalid_State("DLP group cannot be used uninitialized");
   }

/*************************************************
* Verify the parameters                          *
*************************************************/
bool DL_Group::verify_group(bool strong) const
   {
   init_check();

   if(g < 2 || p < 3 || q < 0)
      return false;
   if((q != 0) && ((p - 1) % q != 0))
      return false;

   if(!strong)
      return true;

   if(!check_prime(p))
      return false;
   if((q > 0) && !check_prime(q))
      return false;
   return true;
   }

/*************************************************
* Return the prime                               *
*************************************************/
const BigInt& DL_Group::get_p() const
   {
   init_check();
   return p;
   }

/*************************************************
* Return the generator                           *
*************************************************/
const BigInt& DL_Group::get_g() const
   {
   init_check();
   return g;
   }

/*************************************************
* Return the subgroup                            *
*************************************************/
const BigInt& DL_Group::get_q() const
   {
   init_check();
   if(q == 0)
      throw Format_Error("DLP group has no q prime specified");
   return q;
   }

/*************************************************
* DER encode the parameters                      *
*************************************************/
SecureVector<byte> DL_Group::DER_encode(Format format) const
   {
   init_check();

   if((q == 0) && (format != PKCS_3))
      throw Encoding_Error("The ANSI DL parameter formats require a subgroup");

   if(format == ANSI_X9_57)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(p)
            .encode(q)
            .encode(g)
         .end_cons()
      .get_contents();
      }
   else if(format == ANSI_X9_42)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(p)
            .encode(g)
            .encode(q)
         .end_cons()
      .get_contents();
      }
   else if(format == PKCS_3)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(p)
            .encode(g)
         .end_cons()
      .get_contents();
      }

   throw Invalid_Argument("Unknown DL_Group encoding " + to_string(format));
   }

/*************************************************
* PEM encode the parameters                      *
*************************************************/
std::string DL_Group::PEM_encode(Format format) const
   {
   SecureVector<byte> encoding = DER_encode(format);
   if(format == PKCS_3)
      return PEM_Code::encode(encoding, "DH PARAMETERS");
   else if(format == ANSI_X9_57)
      return PEM_Code::encode(encoding, "DSA PARAMETERS");
   else if(format == ANSI_X9_42)
      return PEM_Code::encode(encoding, "X942 DH PARAMETERS");
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + to_string(format));
   }

/*************************************************
* Decode BER encoded parameters                  *
*************************************************/
void DL_Group::BER_decode(DataSource& source, Format format)
   {
   BigInt new_p, new_q, new_g;

   BER_Decoder decoder(source);
   BER_Decoder ber = decoder.start_cons(SEQUENCE);

   if(format == ANSI_X9_57)
      {
      ber.decode(new_p)
         .decode(new_q)
         .decode(new_g)
         .verify_end();
      }
   else if(format == ANSI_X9_42)
      {
      ber.decode(new_p)
         .decode(new_g)
         .decode(new_q)
         .discard_remaining();
      }
   else if(format == PKCS_3)
      {
      ber.decode(new_p)
         .decode(new_g)
         .discard_remaining();
      }
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + to_string(format));

   initialize(new_p, new_q, new_g);
   }

/*************************************************
* Decode PEM encoded parameters                  *
*************************************************/
void DL_Group::PEM_decode(DataSource& source)
   {
   std::string label;
   DataSource_Memory ber(PEM_Code::decode(source, label));

   if(label == "DH PARAMETERS")
      BER_decode(ber, PKCS_3);
   else if(label == "DSA PARAMETERS")
      BER_decode(ber, ANSI_X9_57);
   else if(label == "X942 DH PARAMETERS")
      BER_decode(ber, ANSI_X9_42);
   else
      throw Decoding_Error("DL_Group: Invalid PEM label " + label);
   }

/*************************************************
* Create a random DSA-style generator            *
*************************************************/
BigInt DL_Group::make_dsa_generator(const BigInt& p, const BigInt& q)
   {
   BigInt g, e = (p - 1) / q;

   for(u32bit j = 0; j != PRIME_TABLE_SIZE; ++j)
      {
      g = power_mod(PRIMES[j], e, p);
      if(g != 1)
         break;
      }

   if(g == 1)
      throw Exception("DL_Group: Couldn't create a suitable generator");

   return g;
   }

}
