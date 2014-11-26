/**
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Distributed under the terms of the Botan license
 *
 */

#ifndef __gf2m_rootfind_dcmp__H_
#define __gf2m_rootfind_dcmp__H_

#include <botan/polyn_gf2m.h>
namespace Botan
{
  /**
   * Find the roots of a polynomial over GF(2^m) using the method by Federenko
   * et al.
   */
  secure_vector<gf2m> find_roots_gf2m_decomp(const polyn_gf2m & polyn, u32bit code_length);

} // end namespace Botan

#endif /* h-guard */
