/*
* HKDF
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hkdf.h>

namespace Botan {

std::string HKDF::name() const
   {
   const std::string prf = m_prf->name();
   const std::string ext = m_extractor->name();

   if(prf == ext)
      return "HKDF(" + prf + ")";
   return "HKDF(" + ext + "," + prf + ")";
   }

void HKDF::clear()
   {
   m_extractor->clear();
   m_prf->clear();
   }

void HKDF::start_extract(const byte salt[], size_t salt_len)
   {
   m_extractor->set_key(salt, salt_len);
   }

void HKDF::extract(const byte input[], size_t input_len)
   {
   m_extractor->update(input, input_len);
   }

void HKDF::finish_extract()
   {
   m_prf->set_key(m_extractor->final());
   }

void HKDF::expand(byte output[], size_t output_len,
                  const byte info[], size_t info_len)
   {
   if(output_len > m_prf->output_length() * 255)
      throw std::invalid_argument("HKDF requested output too large");

   byte counter = 1;

   secure_vector<byte> T;

   while(output_len)
      {
      m_prf->update(T);
      m_prf->update(info, info_len);
      m_prf->update(counter++);
      m_prf->final(T);

      const size_t to_write = std::min(T.size(), output_len);
      copy_mem(&output[0], &T[0], to_write);
      output += to_write;
      output_len -= to_write;
      }
   }

}
