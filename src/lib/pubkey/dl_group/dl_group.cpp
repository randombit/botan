/*
* Discrete Logarithm Parameters
* (C) 1999-2008,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dl_group.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pem.h>
#include <botan/workfactor.h>
#include <botan/internal/monty_exp.h>
#include <map>

namespace Botan {

class DL_Group_Data final
   {
   public:
      DL_Group_Data(const BigInt& p, const BigInt& q, const BigInt& g) :
         m_p(p), m_q(q), m_g(g),
         m_mod_p(p),
         m_monty(monty_precompute(m_g, m_p, m_mod_p, /*window bits=*/4)),
         m_p_bits(p.bits())
         {}

      ~DL_Group_Data() = default;

      DL_Group_Data(const DL_Group_Data& other) = delete;
      DL_Group_Data& operator=(const DL_Group_Data& other) = delete;

      const BigInt& p() const { return m_p; }
      const BigInt& q() const { return m_q; }
      const BigInt& g() const { return m_g; }

      BigInt mod_p(const BigInt& x) const { return m_mod_p.reduce(x); }

      BigInt multiply_mod_p(const BigInt& x, const BigInt& y) const
         {
         return m_mod_p.multiply(x, y);
         }

      size_t p_bits() const { return m_p_bits; }
      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      BigInt power_g_p(const BigInt& k) const { return monty_execute(*m_monty, k); }

   private:
      BigInt m_p;
      BigInt m_q;
      BigInt m_g;
      Modular_Reducer m_mod_p;
      std::shared_ptr<const Montgomery_Exponentation_State> m_monty;
      size_t m_p_bits;
   };

//static
std::shared_ptr<DL_Group_Data> DL_Group::BER_decode_DL_group(const uint8_t data[], size_t data_len, DL_Group::Format format)
   {
   BigInt p, q, g;

   BER_Decoder decoder(data, data_len);
   BER_Decoder ber = decoder.start_cons(SEQUENCE);

   if(format == DL_Group::ANSI_X9_57)
      {
      ber.decode(p)
         .decode(q)
         .decode(g)
         .verify_end();
      }
   else if(format == DL_Group::ANSI_X9_42)
      {
      ber.decode(p)
         .decode(g)
         .decode(q)
         .discard_remaining();
      }
   else if(format == DL_Group::PKCS_3)
      {
      // q is left as zero
      ber.decode(p)
         .decode(g)
         .discard_remaining();
      }
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + std::to_string(format));

   return std::make_shared<DL_Group_Data>(p, q, g);
   }

//static
std::shared_ptr<DL_Group_Data>
DL_Group::load_DL_group_info(const char* p_str,
                             const char* q_str,
                             const char* g_str)
   {
   const BigInt p(p_str);
   const BigInt q(q_str);
   const BigInt g(g_str);

   return std::make_shared<DL_Group_Data>(p, q, g);
   }

//static
std::shared_ptr<DL_Group_Data>
DL_Group::load_DL_group_info(const char* p_str,
                             const char* g_str)
   {
   const BigInt p(p_str);
   const BigInt q = (p - 1) / 2;
   const BigInt g(g_str);

   return std::make_shared<DL_Group_Data>(p, q, g);
   }

namespace {

DL_Group::Format pem_label_to_dl_format(const std::string& label)
   {
   if(label == "DH PARAMETERS")
      return DL_Group::PKCS_3;
   else if(label == "DSA PARAMETERS")
      return DL_Group::ANSI_X9_57;
   else if(label == "X942 DH PARAMETERS" || label == "X9.42 DH PARAMETERS")
      return DL_Group::ANSI_X9_42;
   else
      throw Decoding_Error("DL_Group: Invalid PEM label " + label);
   }

}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const std::string& str)
   {
   // Either a name or a PEM block, try name first
   m_data = DL_group_info(str);

   if(m_data == nullptr)
      {
      try
         {
         std::string label;
         const std::vector<uint8_t> ber = unlock(PEM_Code::decode(str, label));
         Format format = pem_label_to_dl_format(label);

         m_data = BER_decode_DL_group(ber.data(), ber.size(), format);
         }
      catch(...) {}
      }

   if(m_data == nullptr)
      throw Invalid_Argument("DL_Group: Unknown group " + str);
   }

namespace {

/*
* Create generator of the q-sized subgroup (DSA style generator)
*/
BigInt make_dsa_generator(const BigInt& p, const BigInt& q)
   {
   const BigInt e = (p - 1) / q;

   if(e == 0 || (p - 1) % q > 0)
      throw Invalid_Argument("make_dsa_generator q does not divide p-1");

   for(size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
      {
      // TODO precompute!
      BigInt g = power_mod(PRIMES[i], e, p);
      if(g > 1)
         return g;
      }

   throw Internal_Error("DL_Group: Couldn't create a suitable generator");
   }

}

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator& rng,
                   PrimeType type, size_t pbits, size_t qbits)
   {
   if(pbits < 1024)
      throw Invalid_Argument("DL_Group: prime size " + std::to_string(pbits) + " is too small");

   if(type == Strong)
      {
      const BigInt p = random_safe_prime(rng, pbits);
      const BigInt q = (p - 1) / 2;

      /*
      Always choose a generator that is quadratic reside mod p,
      this forces g to be a generator of the subgroup of size q.
      */
      BigInt g = 2;
      if(jacobi(g, p) != 1)
         {
         // prime table does not contain 2
         for(size_t i = 0; i < PRIME_TABLE_SIZE; ++i)
            {
            g = PRIMES[i];
            if(jacobi(g, p) == 1)
               break;
            }
         }

      m_data = std::make_shared<DL_Group_Data>(p, q, g);
      }
   else if(type == Prime_Subgroup)
      {
      if(qbits == 0)
         qbits = dl_exponent_size(pbits);

      const BigInt q = random_prime(rng, qbits);
      Modular_Reducer mod_2q(2*q);
      BigInt X;
      BigInt p;
      while(p.bits() != pbits || !is_prime(p, rng))
         {
         X.randomize(rng, pbits);
         p = X - mod_2q.reduce(X) + 1;
         }

      const BigInt g = make_dsa_generator(p, q);
      m_data = std::make_shared<DL_Group_Data>(p, q, g);
      }
   else if(type == DSA_Kosherizer)
      {
      if(qbits == 0)
         qbits = ((pbits <= 1024) ? 160 : 256);

      BigInt p, q;
      generate_dsa_primes(rng, p, q, pbits, qbits);
      const BigInt g = make_dsa_generator(p, q);
      m_data = std::make_shared<DL_Group_Data>(p, q, g);
      }
   else
      {
      throw Invalid_Argument("DL_Group unknown PrimeType");
      }
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(RandomNumberGenerator& rng,
                   const std::vector<uint8_t>& seed,
                   size_t pbits, size_t qbits)
   {
   BigInt p, q;

   if(!generate_dsa_primes(rng, p, q, pbits, qbits, seed))
      throw Invalid_Argument("DL_Group: The seed given does not generate a DSA group");

   BigInt g = make_dsa_generator(p, q);

   m_data = std::make_shared<DL_Group_Data>(p, q, g);
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const BigInt& p, const BigInt& g)
   {
   m_data = std::make_shared<DL_Group_Data>(p, 0, g);
   }

/*
* DL_Group Constructor
*/
DL_Group::DL_Group(const BigInt& p, const BigInt& q, const BigInt& g)
   {
   m_data = std::make_shared<DL_Group_Data>(p, q, g);
   }

const DL_Group_Data& DL_Group::data() const
   {
   if(m_data)
      return *m_data;

   throw Invalid_State("DL_Group uninitialized");
   }

/*
* Verify the parameters
*/
bool DL_Group::verify_group(RandomNumberGenerator& rng,
                            bool strong) const
   {
   if(get_g() < 2 || get_p() < 3 || get_q() < 0)
      return false;

   const size_t prob = (strong) ? 128 : 10;

   if(get_q() != 0)
      {
      if((get_p() - 1) % get_q() != 0)
         {
         return false;
         }
      if(this->power_g_p(get_q()) != 1)
         {
         return false;
         }
      if(!is_prime(get_q(), rng, prob))
         {
         return false;
         }
      }

   if(!is_prime(get_p(), rng, prob))
      {
      return false;
      }
   return true;
   }

/*
* Return the prime
*/
const BigInt& DL_Group::get_p() const
   {
   return data().p();
   }

/*
* Return the generator
*/
const BigInt& DL_Group::get_g() const
   {
   return data().g();
   }

/*
* Return the subgroup
*/
const BigInt& DL_Group::get_q() const
   {
   return data().q();
   }

size_t DL_Group::p_bits() const
   {
   return data().p_bits();
   }

size_t DL_Group::p_bytes() const
   {
   return data().p_bytes();
   }

BigInt DL_Group::inverse_mod_p(const BigInt& x) const
   {
   // precompute??
   return inverse_mod(x, get_p());
   }

BigInt DL_Group::mod_p(const BigInt& x) const
   {
   return data().mod_p(x);
   }

BigInt DL_Group::multiply_mod_p(const BigInt& x, const BigInt& y) const
   {
   return data().multiply_mod_p(x, y);
   }

BigInt DL_Group::power_g_p(const BigInt& x) const
   {
   return data().power_g_p(x);
   }

/*
* DER encode the parameters
*/
std::vector<uint8_t> DL_Group::DER_encode(Format format) const
   {
   if(format == ANSI_X9_57)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(get_p())
            .encode(get_q())
            .encode(get_g())
         .end_cons()
      .get_contents_unlocked();
      }
   else if(format == ANSI_X9_42)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(get_p())
            .encode(get_g())
            .encode(get_q())
         .end_cons()
      .get_contents_unlocked();
      }
   else if(format == PKCS_3)
      {
      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(get_p())
            .encode(get_g())
         .end_cons()
      .get_contents_unlocked();
      }

   throw Invalid_Argument("Unknown DL_Group encoding " + std::to_string(format));
   }

/*
* PEM encode the parameters
*/
std::string DL_Group::PEM_encode(Format format) const
   {
   const std::vector<uint8_t> encoding = DER_encode(format);

   if(format == PKCS_3)
      return PEM_Code::encode(encoding, "DH PARAMETERS");
   else if(format == ANSI_X9_57)
      return PEM_Code::encode(encoding, "DSA PARAMETERS");
   else if(format == ANSI_X9_42)
      return PEM_Code::encode(encoding, "X9.42 DH PARAMETERS");
   else
      throw Invalid_Argument("Unknown DL_Group encoding " + std::to_string(format));
   }

DL_Group::DL_Group(const uint8_t ber[], size_t ber_len, Format format)
   {
   m_data = BER_decode_DL_group(ber, ber_len, format);
   }

void DL_Group::BER_decode(const std::vector<uint8_t>& ber, Format format)
   {
   m_data = BER_decode_DL_group(ber.data(), ber.size(), format);
   }

/*
* Decode PEM encoded parameters
*/
void DL_Group::PEM_decode(const std::string& pem)
   {
   std::string label;
   const std::vector<uint8_t> ber = unlock(PEM_Code::decode(pem, label));
   Format format = pem_label_to_dl_format(label);

   m_data = BER_decode_DL_group(ber.data(), ber.size(), format);
   }

//static
std::string DL_Group::PEM_for_named_group(const std::string& name)
   {
   DL_Group group(name);
   DL_Group::Format format = group.get_q().is_zero() ? DL_Group::PKCS_3 : DL_Group::ANSI_X9_42;
   return group.PEM_encode(format);
   }

}
