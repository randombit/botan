/*
* EAC1_1 objects
* (C) 2008 Falko Strenzke
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAC_OBJ_H__
#define BOTAN_EAC_OBJ_H__

#include <botan/ecdsa_sig.h>
#include <botan/signed_obj.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <memory>
#include <string>

namespace Botan {

/*
* TR03110 v1.1 EAC CV Certificate
*/
template<typename Derived> // CRTP is used enable the call sequence:
class BOTAN_DLL EAC1_1_obj : public EAC_Signed_Object
   {
      // data members first:
   protected:

      ECDSA_Signature m_sig;

      // member functions here:
   public:
      /**
      * Return the signature as a concatenation of the encoded parts.
      * @result the concatenated signature
      */
      SecureVector<byte> get_concat_sig() const;

      /**
      * Verify the signature of this objects.
      * @param pub_key the public key to verify the signature with
      * @result true if the verification succeeded
      */
      virtual bool check_signature(Public_Key& pub_key) const;

   protected:
      void init(DataSource& in);

      virtual ~EAC1_1_obj<Derived>(){}

   };

template<typename Derived>
SecureVector<byte> EAC1_1_obj<Derived>::get_concat_sig() const
   {
   return m_sig.get_concatenation();
   }

template<typename Derived>
void EAC1_1_obj<Derived>::init(DataSource& in)
   {
   try
      {
      Derived::decode_info(in, tbs_bits, m_sig);
      }
   catch(Decoding_Error)
      {
      throw Decoding_Error(PEM_label_pref + " decoding failed");
      }
   }

template<typename Derived>
bool EAC1_1_obj<Derived>::check_signature(Public_Key& pub_key) const
   {
   try
      {
      std::vector<std::string> sig_info =
         split_on(OIDS::lookup(sig_algo.oid), '/');

      if(sig_info.size() != 2 || sig_info[0] != pub_key.algo_name())
         {
         return false;
         }

      std::string padding = sig_info[1];
      Signature_Format format =
         (pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;

      if(!dynamic_cast<PK_Verifying_wo_MR_Key*>(&pub_key))
         return false;

      SecureVector<byte> seq_sig = m_sig.DER_encode();
      SecureVector<byte> to_sign = tbs_data();

      PK_Verifying_wo_MR_Key& sig_key = dynamic_cast<PK_Verifying_wo_MR_Key&>(pub_key);
      std::auto_ptr<PK_Verifier> verifier(get_pk_verifier(sig_key, padding, format));
      return verifier->verify_message(to_sign, seq_sig);
      }
   catch(...)
      {
      return false;
      }
   }

}

#endif
