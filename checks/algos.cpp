
#include <botan/botan.h>
#include <string>
using namespace Botan;

#include "common.h"

std::vector<algorithm> get_algos()
   {
   std::vector<algorithm> algos;

   algos.push_back(algorithm("Block Cipher", "AES-128", "AES-128/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "AES-192", "AES-192/ECB", 24));
   algos.push_back(algorithm("Block Cipher", "AES-256", "AES-256/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "Blowfish", "Blowfish/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "CAST-128", "CAST-128/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "CAST-256", "CAST-256/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "DES", "DES/ECB", 8));
   algos.push_back(algorithm("Block Cipher", "DESX", "DESX/ECB", 24));
   algos.push_back(algorithm("Block Cipher", "TripleDES",
                             "TripleDES/ECB", 24));
   algos.push_back(algorithm("Block Cipher", "GOST", "GOST/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "IDEA", "IDEA/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "KASUMI", "KASUMI/ECB", 16));

   algos.push_back(algorithm("Block Cipher",
                             "Lion",
                             "Lion(SHA-256,Turing,8192)/ECB", 32));

   algos.push_back(algorithm("Block Cipher", "Luby-Rackoff(SHA-512)",
                             "Luby-Rackoff(SHA-512)/ECB", 16));

   algos.push_back(algorithm("Block Cipher", "MARS", "MARS/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "MISTY1", "MISTY1/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "Noekeon", "Noekeon/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "RC2", "RC2/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "RC5(12)", "RC5(12)/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "RC5(16)", "RC5(16)/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "RC6", "RC6/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "SAFER-SK(10)",
                             "SAFER-SK(10)/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "SEED", "SEED/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "Serpent", "Serpent/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "Skipjack", "Skipjack/ECB", 10));
   algos.push_back(algorithm("Block Cipher", "Square", "Square/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "TEA", "TEA/ECB", 16));
   algos.push_back(algorithm("Block Cipher", "Twofish", "Twofish/ECB", 32));
   algos.push_back(algorithm("Block Cipher", "XTEA", "XTEA/ECB", 16));

   algos.push_back(algorithm("Cipher Mode", "DES/CBC/PKCS7", 8, 8));
   algos.push_back(algorithm("Cipher Mode", "TripleDES/CBC/PKCS7", 24, 8));

   algos.push_back(algorithm("Cipher Mode", "AES-128/CBC/PKCS7", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CBC/CTS", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CFB(128)", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CFB(64)", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CFB(32)", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CFB(16)", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CFB(8)", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/OFB", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/CTR",
                             "AES-128/CTR-BE", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/EAX", 16, 16));
   algos.push_back(algorithm("Cipher Mode", "AES-128/XTS", 32, 16));

   algos.push_back(algorithm("Stream Cipher", "ARC4", 16));
   algos.push_back(algorithm("Stream Cipher", "Salsa20", 32));
   algos.push_back(algorithm("Stream Cipher", "Turing", 32));
   algos.push_back(algorithm("Stream Cipher", "WiderWake4+1",
                             "WiderWake4+1-BE", 16, 8));

   algos.push_back(algorithm("Hash", "Adler32"));
   algos.push_back(algorithm("Hash", "CRC24"));
   algos.push_back(algorithm("Hash", "CRC32"));
   algos.push_back(algorithm("Hash", "FORK-256"));
   algos.push_back(algorithm("Hash", "GOST-34.11"));
   algos.push_back(algorithm("Hash", "HAS-160"));
   algos.push_back(algorithm("Hash", "HAS-V"));
   algos.push_back(algorithm("Hash", "MD2"));
   algos.push_back(algorithm("Hash", "MD4"));
   algos.push_back(algorithm("Hash", "MD5"));
   algos.push_back(algorithm("Hash", "RIPEMD-128"));
   algos.push_back(algorithm("Hash", "RIPEMD-160"));
   algos.push_back(algorithm("Hash", "SHA-160"));
   algos.push_back(algorithm("Hash", "SHA-256"));
   algos.push_back(algorithm("Hash", "SHA-384"));
   algos.push_back(algorithm("Hash", "SHA-512"));
   algos.push_back(algorithm("Hash", "Skein-512"));
   algos.push_back(algorithm("Hash", "Tiger"));
   algos.push_back(algorithm("Hash", "Whirlpool"));

   algos.push_back(algorithm("MAC", "CMAC(AES-128)", 16));
   algos.push_back(algorithm("MAC", "HMAC(SHA-1)", 16));
   algos.push_back(algorithm("MAC", "X9.19-MAC", 16));

   algos.push_back(algorithm("RNG", "AutoSeeded", 4096));
   algos.push_back(algorithm("RNG", "HMAC_RNG", 4096));
   algos.push_back(algorithm("RNG", "Randpool", 4096));
   algos.push_back(algorithm("RNG", "X9.31-RNG", 4096));

   algos.push_back(algorithm("Codec", "Base64_Encode"));
   algos.push_back(algorithm("Codec", "Base64_Decode"));

   return algos;
   }
