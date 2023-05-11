/*
 * SPHINCS+
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SPHINCS_PLUS_H_
#define BOTAN_SPHINCS_PLUS_H_

#include <botan/sp_parameters.h>

#include <memory>
#include <vector>

namespace Botan {

// TODO: Implement me

// Temporary sign function without class
std::vector<uint8_t> sphincsplus_sign(const std::vector<uint8_t>& message,
                                      const secure_vector<uint8_t>& sk_seed_vec,
                                      const secure_vector<uint8_t>& sk_prf_vec,
                                      const std::vector<uint8_t>& pub_seed_vec,
                                      const std::vector<uint8_t>& opt_rand_vec,
                                      const std::vector<uint8_t>& pk_root,
                                      const Sphincs_Parameters& params);

}

#endif
