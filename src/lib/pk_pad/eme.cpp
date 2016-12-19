/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_EME_OAEP)
  #include <botan/oaep.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
  #include <botan/eme_pkcs.h>
#endif

#if defined(BOTAN_HAS_EME_RAW)
  #include <botan/eme_raw.h>
#endif

namespace Botan {

EME* get_eme(const std::string& algo_spec) {
#if defined(BOTAN_HAS_EME_RAW)
  if (algo_spec == "Raw") {
    return new EME_Raw;
  }
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
  if (algo_spec == "PKCS1v15" || algo_spec == "EME-PKCS1-v1_5") {
    return new EME_PKCS1v15;
  }
#endif

#if defined(BOTAN_HAS_EME_OAEP)
  SCAN_Name req(algo_spec);

  if (req.algo_name() == "OAEP" ||
      req.algo_name() == "EME-OAEP" ||
      req.algo_name() == "EME1") {
    if (req.arg_count() == 1 ||
        (req.arg_count() == 2 && req.arg(1) == "MGF1")) {
      if (auto hash = HashFunction::create(req.arg(0))) {
        return new OAEP(hash.release());
      }
    }
  }
#endif

  throw Algorithm_Not_Found(algo_spec);
}

/*
* Encode a message
*/
secure_vector<uint8_t> EME::encode(const uint8_t msg[], size_t msg_len,
                                   size_t key_bits,
                                   RandomNumberGenerator& rng) const {
  return pad(msg, msg_len, key_bits, rng);
}

/*
* Encode a message
*/
secure_vector<uint8_t> EME::encode(const secure_vector<uint8_t>& msg,
                                   size_t key_bits,
                                   RandomNumberGenerator& rng) const {
  return pad(msg.data(), msg.size(), key_bits, rng);
}


}
