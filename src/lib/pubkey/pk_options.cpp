/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_options.h>

#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

namespace Botan {

PK_Signature_Options PK_Signature_Options::with_padding(std::string_view padding) const {
   BOTAN_STATE_CHECK_MSG(!using_padding(), "PK_Signature_Options::with_padding cannot specify padding twice");
   auto next = (*this);
   next.m_padding = padding;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_prehash(std::optional<std::string> prehash_fn) const {
   BOTAN_STATE_CHECK_MSG(!using_prehash(), "PK_Signature_Options::with_prehash cannot specify prehash twice");
   auto next = (*this);
   next.m_use_prehash = true;
   next.m_prehash = std::move(prehash_fn);
   return next;
}

PK_Signature_Options PK_Signature_Options::with_provider(std::string_view provider) const {
   if(provider.empty()) {
      return (*this);
   }

   BOTAN_STATE_CHECK_MSG(!using_provider(), "PK_Signature_Options::with_provider cannot specify provider twice");
   auto next = (*this);
   next.m_provider = provider;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_context(std::span<const uint8_t> context) const {
   BOTAN_STATE_CHECK_MSG(!using_context(), "PK_Signature_Options::with_context cannot specify context twice");
   auto next = (*this);
   next.m_context = std::vector<uint8_t>(context.begin(), context.end());
   return next;
}

PK_Signature_Options PK_Signature_Options::with_context(std::string_view context) const {
   return this->with_context(std::span{cast_char_ptr_to_uint8(context.data()), context.size()});
}

PK_Signature_Options PK_Signature_Options::with_deterministic_signature() const {
   auto next = (*this);
   next.m_deterministic_sig = true;
   return next;
}

PK_Signature_Options PK_Signature_Options::with_der_encoded_signature() const {
   auto next = (*this);
   next.m_use_der = true;
   return next;
}

std::string PK_Signature_Options::_padding_with_hash() const {
   if(!m_hash_fn.empty() && m_padding.has_value()) {
      return fmt("{}({})", m_padding.value(), m_hash_fn);
   }

   if(m_padding.has_value()) {
      return m_padding.value();
   }

   if(!m_hash_fn.empty()) {
      return m_hash_fn;
   }

   throw Invalid_Argument("RSA signature requires a padding scheme");
}

//static
PK_Signature_Options PK_Signature_Options::_parse(const Public_Key& key,
                                                  std::string_view params,
                                                  Signature_Format format) {
   /*
   * This is a convoluted mess because we must handle dispatch for every algorithm
   * specific detail of how padding strings were formatted in versions prior to 3.6.
   *
   * This will all go away once the deprecated constructors of PK_Signer and PK_Verifier
   * are removed in Botan4.
   */

   if(key.algo_name().starts_with("Dilithium")) {
      BOTAN_ARG_CHECK(params.empty() || params == "Randomized" || params == "Deterministic",
                      "Unexpected parameters for signing with Dilithium");

      if(params == "Deterministic") {
         return PK_Signature_Options().with_deterministic_signature();
      } else {
         return PK_Signature_Options();
      }
   }

   if(key.algo_name() == "SM2") {
      /*
      * SM2 parameters have the following possible formats:
      * Ident [since 2.2.0]
      * Ident,Hash [since 2.3.0]
      */
      if(params.empty()) {
         return PK_Signature_Options("SM3");
      } else {
         std::string userid;
         std::string hash = "SM3";
         auto comma = params.find(',');
         if(comma == std::string::npos) {
            userid = params;
         } else {
            userid = params.substr(0, comma);
            hash = params.substr(comma + 1, std::string::npos);
         }
         return PK_Signature_Options(hash).with_context(userid);
      }
   }

   if(key.algo_name() == "Ed25519") {
      if(params.empty() || params == "Identity" || params == "Pure") {
         return PK_Signature_Options();
      } else if(params == "Ed25519ph") {
         return PK_Signature_Options().with_prehash();
      } else {
         return PK_Signature_Options().with_prehash(std::string(params));
      }
   }

   if(key.algo_name() == "Ed448") {
      if(params.empty() || params == "Identity" || params == "Pure" || params == "Ed448") {
         return PK_Signature_Options();
      } else if(params == "Ed448ph") {
         return PK_Signature_Options().with_prehash();
      } else {
         return PK_Signature_Options().with_prehash(std::string(params));
      }
   }

   if(key.algo_name() == "RSA") {
      return PK_Signature_Options().with_padding(params);
   }

   if(params.empty()) {
      return PK_Signature_Options();
   }

   // ECDSA/DSA/ECKCDSA/etc
   auto dsa_options = [&]() {
      if(params.starts_with("EMSA1")) {
         SCAN_Name req(params);
         return PK_Signature_Options(req.arg(0));
      } else {
         return PK_Signature_Options(params);
      }
   }();

   if(format == Signature_Format::DerSequence) {
      return dsa_options.with_der_encoded_signature();
   } else {
      return dsa_options;
   }
}

}  // namespace Botan
