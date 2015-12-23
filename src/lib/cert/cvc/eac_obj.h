/*
* EAC1_1 objects
* (C) 2008 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EAC_OBJ_H__
#define BOTAN_EAC_OBJ_H__

#include <botan/signed_obj.h>
#include <botan/ecdsa_sig.h>

namespace Botan {

/**
* TR03110 v1.1 EAC CV Certificate
*/
template<typename Derived> // CRTP is used enable the call sequence:
class EAC1_1_obj : public EAC_Signed_Object
   {
   public:
      /**
      * Return the signature as a concatenation of the encoded parts.
      * @result the concatenated signature
      */
      std::vector<byte> get_concat_sig() const
         { return m_sig.get_concatenation(); }

      bool check_signature(class Public_Key& key) const
         {
         return EAC_Signed_Object::check_signature(key, m_sig.DER_encode());
         }

   protected:
      ECDSA_Signature m_sig;

      void init(DataSource& in)
         {
         try
            {
            Derived::decode_info(in, m_tbs_bits, m_sig);
            }
         catch(Decoding_Error)
            {
            throw Decoding_Error(m_PEM_label_pref + " decoding failed");
            }
         }

      virtual ~EAC1_1_obj<Derived>(){}
   };

}

#endif
