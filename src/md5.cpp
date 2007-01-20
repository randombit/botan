/*************************************************
* MD5 Source File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/md5.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace {

/*************************************************
* MD5 FF Function                                *
*************************************************/
inline void FF(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
               byte S, u32bit magic)
   {
   A += (D ^ (B & (C ^ D))) + msg + magic;
   A  = rotate_left(A, S) + B;
   }

/*************************************************
* MD5 GG Function                                *
*************************************************/
inline void GG(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
               byte S, u32bit magic)
   {
   A += (C ^ (D & (B ^ C))) + msg + magic;
   A  = rotate_left(A, S) + B;
   }

/*************************************************
* MD5 HH Function                                *
*************************************************/
inline void HH(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
               byte S, u32bit magic)
   {
   A += (B ^ C ^ D) + msg + magic;
   A  = rotate_left(A, S) + B;
   }

/*************************************************
* MD5 II Function                                *
*************************************************/
inline void II(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
               byte S, u32bit magic)
   {
   A += (C ^ (B | ~D)) + msg + magic;
   A  = rotate_left(A, S) + B;
   }

}

/*************************************************
* MD5 Compression Function                       *
*************************************************/
void MD5::hash(const byte input[])
   {
   for(u32bit j = 0; j != 16; ++j)
      M[j] = make_u32bit(input[4*j+3], input[4*j+2], input[4*j+1], input[4*j]);

   u32bit A = digest[0], B = digest[1], C = digest[2], D = digest[3];

   FF(A,B,C,D,M[ 0], 7,0xD76AA478);   FF(D,A,B,C,M[ 1],12,0xE8C7B756);
   FF(C,D,A,B,M[ 2],17,0x242070DB);   FF(B,C,D,A,M[ 3],22,0xC1BDCEEE);
   FF(A,B,C,D,M[ 4], 7,0xF57C0FAF);   FF(D,A,B,C,M[ 5],12,0x4787C62A);
   FF(C,D,A,B,M[ 6],17,0xA8304613);   FF(B,C,D,A,M[ 7],22,0xFD469501);
   FF(A,B,C,D,M[ 8], 7,0x698098D8);   FF(D,A,B,C,M[ 9],12,0x8B44F7AF);
   FF(C,D,A,B,M[10],17,0xFFFF5BB1);   FF(B,C,D,A,M[11],22,0x895CD7BE);
   FF(A,B,C,D,M[12], 7,0x6B901122);   FF(D,A,B,C,M[13],12,0xFD987193);
   FF(C,D,A,B,M[14],17,0xA679438E);   FF(B,C,D,A,M[15],22,0x49B40821);

   GG(A,B,C,D,M[ 1], 5,0xF61E2562);   GG(D,A,B,C,M[ 6], 9,0xC040B340);
   GG(C,D,A,B,M[11],14,0x265E5A51);   GG(B,C,D,A,M[ 0],20,0xE9B6C7AA);
   GG(A,B,C,D,M[ 5], 5,0xD62F105D);   GG(D,A,B,C,M[10], 9,0x02441453);
   GG(C,D,A,B,M[15],14,0xD8A1E681);   GG(B,C,D,A,M[ 4],20,0xE7D3FBC8);
   GG(A,B,C,D,M[ 9], 5,0x21E1CDE6);   GG(D,A,B,C,M[14], 9,0xC33707D6);
   GG(C,D,A,B,M[ 3],14,0xF4D50D87);   GG(B,C,D,A,M[ 8],20,0x455A14ED);
   GG(A,B,C,D,M[13], 5,0xA9E3E905);   GG(D,A,B,C,M[ 2], 9,0xFCEFA3F8);
   GG(C,D,A,B,M[ 7],14,0x676F02D9);   GG(B,C,D,A,M[12],20,0x8D2A4C8A);

   HH(A,B,C,D,M[ 5], 4,0xFFFA3942);   HH(D,A,B,C,M[ 8],11,0x8771F681);
   HH(C,D,A,B,M[11],16,0x6D9D6122);   HH(B,C,D,A,M[14],23,0xFDE5380C);
   HH(A,B,C,D,M[ 1], 4,0xA4BEEA44);   HH(D,A,B,C,M[ 4],11,0x4BDECFA9);
   HH(C,D,A,B,M[ 7],16,0xF6BB4B60);   HH(B,C,D,A,M[10],23,0xBEBFBC70);
   HH(A,B,C,D,M[13], 4,0x289B7EC6);   HH(D,A,B,C,M[ 0],11,0xEAA127FA);
   HH(C,D,A,B,M[ 3],16,0xD4EF3085);   HH(B,C,D,A,M[ 6],23,0x04881D05);
   HH(A,B,C,D,M[ 9], 4,0xD9D4D039);   HH(D,A,B,C,M[12],11,0xE6DB99E5);
   HH(C,D,A,B,M[15],16,0x1FA27CF8);   HH(B,C,D,A,M[ 2],23,0xC4AC5665);

   II(A,B,C,D,M[ 0], 6,0xF4292244);   II(D,A,B,C,M[ 7],10,0x432AFF97);
   II(C,D,A,B,M[14],15,0xAB9423A7);   II(B,C,D,A,M[ 5],21,0xFC93A039);
   II(A,B,C,D,M[12], 6,0x655B59C3);   II(D,A,B,C,M[ 3],10,0x8F0CCC92);
   II(C,D,A,B,M[10],15,0xFFEFF47D);   II(B,C,D,A,M[ 1],21,0x85845DD1);
   II(A,B,C,D,M[ 8], 6,0x6FA87E4F);   II(D,A,B,C,M[15],10,0xFE2CE6E0);
   II(C,D,A,B,M[ 6],15,0xA3014314);   II(B,C,D,A,M[13],21,0x4E0811A1);
   II(A,B,C,D,M[ 4], 6,0xF7537E82);   II(D,A,B,C,M[11],10,0xBD3AF235);
   II(C,D,A,B,M[ 2],15,0x2AD7D2BB);   II(B,C,D,A,M[ 9],21,0xEB86D391);

   digest[0] += A; digest[1] += B; digest[2] += C; digest[3] += D;
   }

/*************************************************
* Copy out the digest                            *
*************************************************/
void MD5::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
      output[j] = get_byte(3 - (j % 4), digest[j/4]);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void MD5::clear() throw()
   {
   MDx_HashFunction::clear();
   M.clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   }

}
