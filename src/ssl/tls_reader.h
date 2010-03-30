/*
* TLS Data Reader
* (C) 2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_READER_H__
#define BOTAN_TLS_READER_H__

#include <botan/secmem.h>
#include <botan/loadstor.h>

namespace Botan {

class TLS_Data_Reader
   {
   public:
      TLS_Data_Reader(const MemoryRegion<byte>& buf_in) :
         buf(buf_in), offset(0) {}

      u16bit get_u16bit()
         {
         assert_at_least(2);
         u16bit result = make_u16bit(buf[offset], buf[offset+1]);
         offset += 2;
         return result;
         }

      byte get_byte()
         {
         assert_at_least(1);
         byte result = buf[offset];
         offset += 1;
         return result;
         }

      template<typename T, typename Container>
      Container get_elem(u32bit num_elems)
         {
         assert_at_least(num_elems * sizeof(T));

         Container result(num_elems);

         for(u32bit i = 0; i != num_elems; ++i)
            result[i] = load_be<T>(&buf[offset], i);

         offset += num_elems * sizeof(T);

         return result;
         }

      template<typename T>
      SecureVector<T> get_range(u32bit len_bytes,
                                u32bit min_elems,
                                u32bit max_elems)
         {
         const u32bit num_elems =
            get_num_elems(len_bytes, sizeof(T), min_elems, max_elems);

         return get_elem<T, SecureVector<T> >(num_elems);
         }

      template<typename T>
      std::vector<T> get_range_vector(u32bit len_bytes,
                                      u32bit min_elems,
                                      u32bit max_elems)
         {
         const u32bit num_elems =
            get_num_elems(len_bytes, sizeof(T), min_elems, max_elems);

         return get_elem<T, std::vector<T> >(num_elems);
         }

      template<typename T>
      SecureVector<T> get_fixed(u32bit size)
         {
         return get_elem<T, SecureVector<T> >(size);
         }

   private:
      u32bit get_length_field(u32bit len_bytes)
         {
         assert_at_least(len_bytes);

         if(len_bytes == 1)
            return get_byte();
         else if(len_bytes == 2)
            return get_u16bit();

         throw Decoding_Error("TLS_Data_Reader: Bad length size");
         }

      u32bit get_num_elems(u32bit len_bytes,
                           u32bit T_size,
                           u32bit min_elems,
                           u32bit max_elems)
         {
         const u32bit byte_length = get_length_field(len_bytes);

         if(byte_length % T_size != 0)
            throw Decoding_Error("TLS_Data_Reader: Size isn't multiple of T");

         const u32bit num_elems = byte_length / T_size;

         if(num_elems < min_elems || num_elems > max_elems)
            throw Decoding_Error("TLS_Data_Reader: Range outside paramaters");

         return num_elems;
         }

      void assert_at_least(u32bit n)
         {
         if(buf.size() - offset < n)
            throw Decoding_Error("TLS_Data_Reader: Corrupt packet");
         }

      const MemoryRegion<byte>& buf;
      u32bit offset;
   };

}

#endif
