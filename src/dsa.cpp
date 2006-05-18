/*************************************************
* DSA Source File                                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/dsa.h>
#include <botan/numthry.h>
#include <botan/keypair.h>

namespace Botan {

/*************************************************
* DSA_PublicKey Constructor                      *
*************************************************/
DSA_PublicKey::DSA_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   X509_load_hook();
   }

/*************************************************
* Algorithm Specific X.509 Initialization Code   *
*************************************************/
void DSA_PublicKey::X509_load_hook()
   {
   core = DSA_Core(group, y);
   check_loaded_public();
   }

/*************************************************
* DSA Verification Function                      *
*************************************************/
bool DSA_PublicKey::verify(const byte msg[], u32bit msg_len,
                           const byte sig[], u32bit sig_len) const
   {
   return core.verify(msg, msg_len, sig, sig_len);
   }

/*************************************************
* Return the maximum input size in bits          *
*************************************************/
u32bit DSA_PublicKey::max_input_bits() const
   {
   return group_q().bits();
   }

/*************************************************
* Return the size of each portion of the sig     *
*************************************************/
u32bit DSA_PublicKey::message_part_size() const
   {
   return group_q().bytes();
   }

/*************************************************
* Create a DSA private key                       *
*************************************************/
DSA_PrivateKey::DSA_PrivateKey(const DL_Group& grp)
   {
   group = grp;
   x = random_integer(2, group_q() - 1);

   PKCS8_load_hook();
   check_generated_private();
   }

/*************************************************
* DSA_PrivateKey Constructor                     *
*************************************************/
DSA_PrivateKey::DSA_PrivateKey(const DL_Group& grp, const BigInt& x1,
                               const BigInt& y1)
   {
   group = grp;
   y = y1;
   x = x1;

   PKCS8_load_hook();
   check_loaded_private();
   }

/*************************************************
* Algorithm Specific PKCS #8 Initialization Code *
*************************************************/
void DSA_PrivateKey::PKCS8_load_hook()
   {
   if(y == 0)
      y = power_mod(group_g(), x, group_p());
   core = DSA_Core(group, y, x);
   }

/*************************************************
* DSA Signature Operation                        *
*************************************************/
SecureVector<byte> DSA_PrivateKey::sign(const byte in[], u32bit length) const
   {
   const BigInt& q = group_q();

   BigInt k;
   do
      k.randomize(q.bits());
   while(k >= q);

   return core.sign(in, length, k);
   }

/*************************************************
* Check Private DSA Parameters                   *
*************************************************/
bool DSA_PrivateKey::check_key(bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(strong) || x >= group_q())
      return false;

   if(!strong)
      return true;

   try {
      KeyPair::check_key(get_pk_signer(*this, "EMSA1(SHA-1)"),
                         get_pk_verifier(*this, "EMSA1(SHA-1)")
         );
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

}
