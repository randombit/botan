/*************************************************
* DL Scheme Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/dl_algo.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

/*************************************************
* Return the X.509 public key encoding           *
*************************************************/
MemoryVector<byte> DL_Scheme_PublicKey::DER_encode_pub() const
   {
   return DER_Encoder().encode(y).get_contents();
   }

/*************************************************
* Return the X.509 parameters encoding           *
*************************************************/
MemoryVector<byte> DL_Scheme_PublicKey::DER_encode_params() const
   {
   return group.DER_encode(group_format());
   }

/*************************************************
* Decode X.509 public key encoding               *
*************************************************/
void DL_Scheme_PublicKey::BER_decode_pub(DataSource& source)
   {
   BER_Decoder(source).decode(y);

   if(y < 2 || y >= group_p())
      throw Invalid_Argument(algo_name() + ": Invalid public key");
   X509_load_hook();
   }

/*************************************************
* Decode X.509 algorithm parameters              *
*************************************************/
void DL_Scheme_PublicKey::BER_decode_params(DataSource& source)
   {
   group.BER_decode(source, group_format());
   }

/*************************************************
* Return the PKCS #8 private key encoding        *
*************************************************/
SecureVector<byte> DL_Scheme_PrivateKey::DER_encode_priv() const
   {
   return DER_Encoder().encode(x).get_contents();
   }

/*************************************************
* Decode a PKCS #8 private key encoding          *
*************************************************/
void DL_Scheme_PrivateKey::BER_decode_priv(DataSource& source)
   {
   BER_Decoder(source).decode(x);

   PKCS8_load_hook();
   check_loaded_private();
   }

/*************************************************
* Check Public DL Parameters                     *
*************************************************/
bool DL_Scheme_PublicKey::check_key(bool strong) const
   {
   if(y < 2 || y >= group_p())
      return false;
   if(!group.verify_group(strong))
      return false;
   return true;
   }

/*************************************************
* Check DL Scheme Private Parameters             *
*************************************************/
bool DL_Scheme_PrivateKey::check_key(bool strong) const
   {
   const BigInt& p = group_p();
   const BigInt& g = group_g();

   if(y < 2 || y >= p || x < 2 || x >= p)
      return false;
   if(!group.verify_group(strong))
      return false;

   if(!strong)
      return true;

   if(y != power_mod(g, x, p))
      return false;

   return true;
   }

}
