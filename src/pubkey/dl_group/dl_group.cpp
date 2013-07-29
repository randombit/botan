/*
* Discrete Logarithm Parameters
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dl_group.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pipe.h>
#include <botan/pem.h>
#include <botan/internal/workfactor.h>

namespace Botan {

/*
* DL_Group Constructor
*/
DL_Group::DL_Group()
   {
   initialized = false;
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const std::string& type)
   {
   const std::string grp_contents = global_state().get("dl", type);

   if(grp_contents == "")
      throw Invalid_Argument("DL_Group: Unknown group " + type);

   PEM_decode(grp_contents);
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator& rng,
                   PrimeType type, size_t pbits, size_t qbits)
   {
   if(pbits < 512)
      throw Invalid_Argument("DL_Group: prime size " + to_string(pbits) +
                             " is too small");

   if(type == Strong)
      {
      p = random_safe_prime(rng, pbits);
      q = (p - 1) / 2;
      g = 2;
      }
   else if(type == Prime_Subgroup)
      {
      if(!qbits)
         qbits = 2 * dl_work_factor(pbits);

      q = random_prime(rng, qbits);
      BigInt X;
      while(p.bits() != pbits || !check_prime(p, rng))
         {
         X.randomize(rng, pbits);
         p = X - (X % (2*q) - 1);
         }

      g = make_dsa_generator(p, q);
      }
   else if(type == DSA_Kosherizer)
      {
      qbits = qbits ? qbits : ((pbits <= 1024) ? 160 : 256);

      generate_dsa_primes(rng,
                          global_state().algorithm_factory(),
                          p, q,
                          pbits, qbits);

      g = make_dsa_generator(p, q);
      }

   initialized = true;
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator& rng,
                   const std::vector<byte>& seed,
                   size_t pbits, size_t qbits)
   {
   if(!generate_dsa_primes(rng,
                           global_state().algorithm_factory(),
                           p, q, pbits, qbits, seed))
      throw Invalid_Argument("DL_Group: The seed given does not "
                             "generate a DSA group");

   g = make_dsa_generator(p, q);

   initialized = true;
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const BigInt& p1, const BigInt& g1)
   {
   initialize(p1, 0, g1);
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const BigInt& p1, const BigInt& q1, const BigInt& g1)
   {
   initialize(p1, q1, g1);
   }

/*
* DL_Group Initializer
*/
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

   initialized = true;
   }

/*
* Verify that the group has been set
*/
void DL_Group::init_check() const
   {
   if(!initialized)
      throw Invalid_State("DLP group cannot be used uninitialized");
   }

/*
* Verify the parameters
*/
bool DL_Group::verify_group(RandomNumberGenerator& rng,
                            bool strong) const
   {
   init_check();

   if(g < 2 || p < 3 || q < 0)
      return false;
   if((q != 0) && ((p - 1) % q != 0))
      return false;

   if(!strong)
      return true;

   if(!check_prime(p, rng))
      return false;
   if((q > 0) && !check_prime(q, rng))
      return false;
   return true;
   }

/*
* Return the prime
*/
const BigInt& DL_Group::get_p() const
   {
   init_check();
   return p;
   }

/*
* Return the generator
*/
const BigInt& DL_Group::get_g() const
   {
   init_check();
   return g;
   }

/*
* Return the subgroup
*/
const BigInt& DL_Group::get_q() const
   {
   init_check();
   if(q == 0)
      throw Invalid_State("DLP group has no q prime specified");
   return q;
   }

/*
* DER encode the parameters
*/
std::vector<byte> DL_Group::DER_encode(Format format) const
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
      .get_contents_unlocked();
      }
   else if(format == ANSI_X9_42)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(p)
            .encode(g)
            .encode(q)
         .end_cons()
      .get_contents_unlocked();
      }
   else if(format == PKCS_3)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(p)
            .encode(g)
         .end_cons()
      .get_contents_unlocked();
      }

   throw Invalid_Argument("Unknown DL_Group encoding " + to_string(format));
   }

/*
* PEM encode the parameters
*/
std::string DL_Group::PEM_encode(Format format) const
   {
   const std::vector<byte> encoding = DER_encode(format);

   if(format == PKCS_3)
      return PEM_Code::encode(encoding, "DH PARAMETERS");
   else if(format == ANSI_X9_57)
      return PEM_Code::encode(encoding, "DSA PARAMETERS");
   else if(format == ANSI_X9_42)
      return PEM_Code::encode(encoding, "X942 DH PARAMETERS");
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + to_string(format));
   }

/*
* Decode BER encoded parameters
*/
void DL_Group::BER_decode(const std::vector<byte>& data,
                          Format format)
   {
   BigInt new_p, new_q, new_g;

   BER_Decoder decoder(data);
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

/*
* Decode PEM encoded parameters
*/
void DL_Group::PEM_decode(const std::string& pem)
   {
   std::string label;

   auto ber = unlock(PEM_Code::decode(pem, label));

   if(label == "DH PARAMETERS")
      BER_decode(ber, PKCS_3);
   else if(label == "DSA PARAMETERS")
      BER_decode(ber, ANSI_X9_57);
   else if(label == "X942 DH PARAMETERS")
      BER_decode(ber, ANSI_X9_42);
   else
      throw Decoding_Error("DL_Group: Invalid PEM label " + label);
   }

/*
* Create generator of the q-sized subgroup (DSA style generator)
*/
BigInt DL_Group::make_dsa_generator(const BigInt& p, const BigInt& q)
   {
   const BigInt e = (p - 1) / q;

   if(e == 0 || (p - 1) % q > 0)
      throw std::invalid_argument("make_dsa_generator q does not divide p-1");

   for(size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
      {
      BigInt g = power_mod(PRIMES[i], e, p);
      if(g > 1)
         return g;
      }

   throw Internal_Error("DL_Group: Couldn't create a suitable generator");
   }

}
