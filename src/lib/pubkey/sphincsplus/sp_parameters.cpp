/*
 * SphincsPlus Parameters
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/exceptn.h>
#include <botan/sp_parameters.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

Sphincs_Parameter_Set set_from_name(std::string_view name)
   {
   if(name == "SphincsPlus-sha2-128s-r3.1" || name == "SphincsPlus-shake-128s-r3.1" || name == "SphincsPlus-haraka-128s-r3.1")
      return Sphincs_Parameter_Set::Sphincs128Small;
   if(name == "SphincsPlus-sha2-128f-r3.1" || name == "SphincsPlus-shake-128f-r3.1" || name == "SphincsPlus-haraka-128f-r3.1")
      return Sphincs_Parameter_Set::Sphincs128Fast;

   if(name == "SphincsPlus-sha2-192s-r3.1" || name == "SphincsPlus-shake-192s-r3.1" || name == "SphincsPlus-haraka-192s-r3.1")
      return Sphincs_Parameter_Set::Sphincs192Small;
   if(name == "SphincsPlus-sha2-192f-r3.1" || name == "SphincsPlus-shake-192f-r3.1" || name == "SphincsPlus-haraka-192f-r3.1")
      return Sphincs_Parameter_Set::Sphincs192Fast;

   if(name == "SphincsPlus-sha2-256s-r3.1" || name == "SphincsPlus-shake-256s-r3.1" || name == "SphincsPlus-haraka-256s-r3.1")
      return Sphincs_Parameter_Set::Sphincs256Small;
   if(name == "SphincsPlus-sha2-256f-r3.1" || name == "SphincsPlus-shake-256f-r3.1" || name == "SphincsPlus-haraka-256f-r3.1")
      return Sphincs_Parameter_Set::Sphincs256Fast;

   throw Lookup_Error(fmt("No SphincsPlus parameter set found for: {}", name));
   }

Sphincs_Hash_Type hash_from_name(std::string_view name)
   {
   if(name == "SphincsPlus-sha2-128s-r3.1" ||
      name == "SphincsPlus-sha2-128f-r3.1"  ||
      name == "SphincsPlus-sha2-192s-r3.1" ||
      name == "SphincsPlus-sha2-192f-r3.1"  ||
      name == "SphincsPlus-sha2-256s-r3.1" ||
      name == "SphincsPlus-sha2-256f-r3.1")
      return Sphincs_Hash_Type::Sha256;
   if(name == "SphincsPlus-shake-128s-r3.1" ||
      name == "SphincsPlus-shake-128f-r3.1"  ||
      name == "SphincsPlus-shake-192s-r3.1" ||
      name == "SphincsPlus-shake-192f-r3.1"  ||
      name == "SphincsPlus-shake-256s-r3.1" ||
      name == "SphincsPlus-shake-256f-r3.1")
      return Sphincs_Hash_Type::Shake256;
   if(name == "SphincsPlus-haraka-128s-r3.1" ||
      name == "SphincsPlus-haraka-128f-r3.1"  ||
      name == "SphincsPlus-haraka-192s-r3.1" ||
      name == "SphincsPlus-haraka-192f-r3.1"  ||
      name == "SphincsPlus-haraka-256s-r3.1" ||
      name == "SphincsPlus-haraka-256f-r3.1")
      return Sphincs_Hash_Type::Haraka;

   throw Lookup_Error(fmt("No SphincsPlus hash instantiation found for: {}", name));
   }


const char* as_string(Sphincs_Hash_Type type)
   {
   switch(type)
      {
      case Sphincs_Hash_Type::Sha256:
         return "sha2";
      case Sphincs_Hash_Type::Shake256:
         return "shake";
      case Sphincs_Hash_Type::Haraka:
         return "haraka";
      }

   Botan::unreachable();
   }

const char* as_string(Sphincs_Parameter_Set set)
   {
   switch(set)
      {
      case Sphincs_Parameter_Set::Sphincs128Small:
         return "128s-r3.1";
      case Sphincs_Parameter_Set::Sphincs128Fast:
         return "128f-r3.1";
      case Sphincs_Parameter_Set::Sphincs192Small:
         return "192s-r3.1";
      case Sphincs_Parameter_Set::Sphincs192Fast:
         return "192f-r3.1";
      case Sphincs_Parameter_Set::Sphincs256Small:
         return "256s-r3.1";
      case Sphincs_Parameter_Set::Sphincs256Fast:
         return "256f-r3.1";
      }

   Botan::unreachable();
   }

}

Sphincs_Parameters::Sphincs_Parameters(Sphincs_Parameter_Set set, Sphincs_Hash_Type hash_type,
                        size_t n, size_t h, size_t d, size_t a, size_t k, size_t w, size_t bitsec)
   : m_set(set), m_hash_type(hash_type)
   , m_n(n), m_h(h), m_d(d), m_a(a), m_k(k), m_w(w), m_bitsec(bitsec)
   {
   BOTAN_ARG_CHECK(w == 4 || w == 16 || w == 256, "Winternitz parameter must be one of 4, 16, 256");
   BOTAN_ARG_CHECK(n == 16 || n == 24 || n == 32, "n must be one of 16, 24, 32");
   BOTAN_ARG_CHECK(m_d > 0, "d must be greater than zero");

   m_xmss_tree_height = m_h / m_d;
   m_log_w = std::floor(log2(m_w));

   // # Winternitz blocks of the message
   m_wots_len1 = (m_n * 8) / m_log_w;

   // # Winternitz blocks of the checksum
   m_wots_len2 = std::floor(log2(m_wots_len1 * (m_w - 1))) / m_log_w + 1;

   // # Winternitz blocks in the signature
   m_wots_len = m_wots_len1 + m_wots_len2;

   // byte length of WOTS+ signature as well as public key
   m_wots_bytes = m_wots_len * m_n;

   m_fors_sig_bytes = (m_a + 1) * m_k * m_n;

   // byte length of the FORS input message
   m_fors_message_bytes = std::ceil((m_a * m_k) / 8.0f);

   m_xmss_sig_bytes = m_wots_bytes + m_xmss_tree_height * m_n;
   m_sp_sig_bytes = m_n /* random */ +
                    m_fors_sig_bytes +
                    m_xmss_sig_bytes * m_d /* height of XMSS Hypertree */;

   m_tree_digest_bytes = std::ceil((m_xmss_tree_height * (m_d - 1)) / 8.0f);
   m_leaf_digest_bytes = std::ceil(m_xmss_tree_height / 8.0f);
   m_h_msg_digest_bytes = m_fors_message_bytes + m_tree_digest_bytes + m_leaf_digest_bytes;
   }


Sphincs_Parameters Sphincs_Parameters::create(Sphincs_Parameter_Set set, Sphincs_Hash_Type hash)
   {
   // See "Table 3" in SPHINCS+ specification (NIST R3.1 submission, page 39)
   switch(set)
      {
      case Sphincs_Parameter_Set::Sphincs128Small:
         return Sphincs_Parameters(set, hash, 16, 63, 7, 12, 14, 16, 133);
      case Sphincs_Parameter_Set::Sphincs128Fast:
         return Sphincs_Parameters(set, hash, 16, 66, 22, 6, 33, 16, 128);

      case Sphincs_Parameter_Set::Sphincs192Small:
         return Sphincs_Parameters(set, hash, 24, 63, 7, 14, 17, 16, 193);
      case Sphincs_Parameter_Set::Sphincs192Fast:
         return Sphincs_Parameters(set, hash, 24, 66, 22, 8, 33, 16, 194);

      case Sphincs_Parameter_Set::Sphincs256Small:
         return Sphincs_Parameters(set, hash, 32, 64, 8, 14, 22, 16, 255);
      case Sphincs_Parameter_Set::Sphincs256Fast:
         return Sphincs_Parameters(set, hash, 32, 68, 17, 9, 35, 16, 255);
      }

   Botan::unreachable();
   }

Sphincs_Parameters Sphincs_Parameters::create(std::string_view name)
   {
   return Sphincs_Parameters::create(set_from_name(name), hash_from_name(name));
   }

std::string Sphincs_Parameters::hash_name() const
   {
   switch(m_hash_type)
      {
      case Sphincs_Hash_Type::Sha256:
         return "SHA-256";
      case Sphincs_Hash_Type::Shake256:
         return fmt("SHAKE-256({})", 8 * n());
      case Sphincs_Hash_Type::Haraka:
         return "Haraka";
      }

   Botan::unreachable();
   }

std::string Sphincs_Parameters::to_string() const
   {
   return fmt("SphincsPlus-{}-{}", as_string(m_hash_type), as_string(m_set));
   }

Sphincs_Parameters Sphincs_Parameters::create(const OID& oid)
   {
   return Sphincs_Parameters::create(oid.to_formatted_string());
   }

OID Sphincs_Parameters::object_identifier() const
   {
   return OID::from_string(to_string());
   }

AlgorithmIdentifier Sphincs_Parameters::algorithm_identifier() const
   {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
   }

}
