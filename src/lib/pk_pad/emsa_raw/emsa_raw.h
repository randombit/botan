/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EMSA_RAW_H__
#define BOTAN_EMSA_RAW_H__

#include <botan/emsa.h>

namespace Botan {

/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
class BOTAN_DLL EMSA_Raw final : public EMSA {
public:
  EMSA* clone() override { return new EMSA_Raw(); }

private:
  void update(const uint8_t[], size_t) override;
  secure_vector<uint8_t> raw_data() override;

  secure_vector<uint8_t> encoding_of(const secure_vector<uint8_t>&, size_t,
                                     RandomNumberGenerator&) override;
  bool verify(const secure_vector<uint8_t>&, const secure_vector<uint8_t>&,
              size_t) override;

  secure_vector<uint8_t> m_message;
};

}

#endif
