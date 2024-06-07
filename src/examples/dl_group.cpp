#include <botan/auto_rng.h>
#include <botan/dl_group.h>
#include <botan/rng.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;
   auto group = std::make_unique<Botan::DL_Group>(rng, Botan::DL_Group::Strong, 2048);

   std::cout << "P = " << group->get_p().to_hex_string() << "\n"
             << "Q = " << group->get_q().to_hex_string() << "\n"
             << "G = " << group->get_g().to_hex_string() << "\n";

   std::cout << "\nPEM:\n" << group->PEM_encode(Botan::DL_Group_Format::ANSI_X9_42) << "\n";

   return 0;
}
