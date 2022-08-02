#include <botan/dl_group.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>

#include <iostream>

int main()
   {
      std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
      std::unique_ptr<Botan::DL_Group> group(new Botan::DL_Group(*rng.get(), Botan::DL_Group::Strong, 2048));
      std::cout << std::endl << "p: " << group->get_p();
      std::cout << std::endl << "q: " << group->get_q();
      std::cout << std::endl << "g: " << group->get_q();
      std::cout << std::endl << "ANSI_X9_42: " << std::endl << group->PEM_encode(Botan::DL_Group_Format::ANSI_X9_42);

   return 0;
   }
