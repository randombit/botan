/* The two headers we guarantee to be parseable as C are ffi.h and build.h */
#include <botan/build.h>

#if defined(BOTAN_HAS_FFI)
   #include <botan/ffi.h>
#else
   #error "The C89 interface is not available in this build"
#endif

#include <stdio.h>
#include <string.h>

#define CHECK_RC(rc)                                                          \
   do {                                                                       \
      if(rc != BOTAN_FFI_SUCCESS) {                                           \
         printf("Call failed rc=%d (%s)\n", rc, botan_error_description(rc)); \
         return 1;                                                            \
      }                                                                       \
   } while(0)

int main() {
   uint8_t digest[32];
   char hex[64 + 1] = {0};
   const char* str_to_hash = "Hello world";
   int rc = 0;

   printf("This is %s\n", botan_version_string());

#if defined(BOTAN_HAS_SHA_256)
   botan_hash_t hash;
   rc = botan_hash_init(&hash, "SHA-256", 0);
   CHECK_RC(rc);

   rc = botan_hash_update(hash, (const uint8_t*)str_to_hash, strlen(str_to_hash));
   CHECK_RC(rc);

   rc = botan_hash_final(hash, digest);
   CHECK_RC(rc);

   rc = botan_hash_destroy(hash);
   CHECK_RC(rc);

   rc = botan_hex_encode(digest, sizeof(digest), hex, sizeof(hex));
   CHECK_RC(rc);

   printf("SHA-256(\"%s\") = %s\n", str_to_hash, hex);

#else
   printf("SHA-256 not included in the build\n");
#endif

   return 0;
}
