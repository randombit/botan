#include <botan/auto_rng.h>
#include <botan/dl_group.h>
#include <botan/rng.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;
   auto group = std::make_unique<Botan::DL_Group>(rng, Botan::DL_Group::Strong, 2048);
   std::cout << std::endl << "p: " << group->get_p();
   std::cout << std::endl << "q: " << group->get_q();
   std::cout << std::endl << "g: " << group->get_q();
   std::cout << std::endl << "ANSI_X9_42: " << std::endl << group->PEM_encode(Botan::DL_Group_Format::ANSI_X9_42);

   return 0;
}
