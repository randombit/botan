#include "apps.h"

int apps_main(const std::string& cmd, int argc, char* argv[])
   {
#define CALL_APP(cmdsym)                           \
   do { if(cmd == #cmdsym) { return cmdsym ##_main (argc - 1, argv + 1); } } while(0)

   CALL_APP(asn1);
   CALL_APP(base64);
   CALL_APP(bcrypt);
   CALL_APP(bzip);
   CALL_APP(ca);
   CALL_APP(factor);
   CALL_APP(fpe);
   CALL_APP(hash);
   CALL_APP(keygen);
   CALL_APP(dsa_sign);
   CALL_APP(dsa_verify);
   CALL_APP(pkcs10);
   CALL_APP(read_ssh);
   CALL_APP(self_sig);
   CALL_APP(tls_client);
   CALL_APP(tls_server);
   CALL_APP(x509);

   return -1;
   }
