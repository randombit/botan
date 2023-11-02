#include <botan/auto_rng.h>
#include <botan/dl_group.h>
#include <botan/rng.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;
   auto group = std::make_unique<Botan::DL_Group>(rng, Botan::DL_Group::Strong, 2048);
   std::cout << "\np: " << group->get_p();
   std::cout << "\nq: " << group->get_q();
   std::cout << "\ng: " << group->get_q();
   std::cout << "\nANSI_X9_42:\n" << group->PEM_encode(Botan::DL_Group_Format::ANSI_X9_42);

   return 0;
}
