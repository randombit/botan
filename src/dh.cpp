/*************************************************
* Diffie-Hellman Source File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/dh.h>
#include <botan/bigintfuncs.h>
#include <botan/util.h>




namespace Botan {

/*************************************************
* DH_PublicKey Constructor                       *
*************************************************/
DH_PublicKey::DH_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   X509_load_hook();
   }

/*************************************************
* Algorithm Specific X.509 Initialization Code   *
*************************************************/
void DH_PublicKey::X509_load_hook()
   {
   load_check();
   }

/*************************************************
* Return the maximum input size in bits          *
*************************************************/
u32bit DH_PublicKey::max_input_bits() const
   {
   return group_p().bits();
   }


/*************************************************
* Create a DH private key                        *
*************************************************/
DH_PrivateKey::DH_PrivateKey(const DL_Group& grp)
   {
   group = grp;

   const BigInt& p = group_p();
   x = random_integer(2 * dl_work_factor(p.bits()));

   PKCS8_load_hook(true);
   }

/*************************************************
* DH_PrivateKey Constructor                      *
*************************************************/
DH_PrivateKey::DH_PrivateKey(const DL_Group& grp, const BigInt& x1,
                             const BigInt& y1)
   {
   group = grp;
   y = y1;
   x = x1;

   PKCS8_load_hook();
   }

/*************************************************
* Algorithm Specific PKCS #8 Initialization Code *
*************************************************/
void DH_PrivateKey::PKCS8_load_hook(bool generated)
   {
   if(y == 0)
      y = power_mod(group_g(), x, group_p());
   core = DH_Core(group, x);

   if(generated)
      gen_check();
   else
      load_check();
   }


/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> DH_PrivateKey::derive_key(const Public_Key& key) const
{
  const DH_PublicKey* p_dh_pk = dynamic_cast<const DH_PublicKey*>(&key);
  if(!p_dh_pk)
  {
   throw Invalid_Argument("DH_PrivateKey::derive_key(): argument must be a DH_PublicKey");
  }
  const BigInt& p = group_p();
  BigInt w = p_dh_pk->get_y();
  if(w <= 1 || w >= p-1)
      throw Invalid_Argument(algo_name() + "::derive_key: Invalid key input");
   return BigInt::encode_1363(core.agree(w), p.bytes());
}
/*SecureVector<byte> DH_PrivateKey::derive_key(const BigInt& w) const
   {
   const BigInt& p = group_p();
   if(w <= 1 || w >= p-1)
      throw Invalid_Argument(algo_name() + "::derive_key: Invalid key input");
   return BigInt::encode_1363(core.agree(w), p.bytes());
   }
*/
}
