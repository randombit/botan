/*
* List of ECC groups
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_group.h>

namespace Botan {

//static
std::string EC_Group::PEM_for_named_group(const std::string& name)
   {
   if(name == "secp160k1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQD////////////////////+//+sczAsBBQAAAAA"
         "AAAAAAAAAAAAAAAAAAAAAAQUAAAAAAAAAAAAAAAAAAAAAAAAAAcEKQQ7TDgs43qh"
         "kqQBnnYwNvT13U1+u5OM+TUxj9zta8KChlMXM8PwPE/uAhUBAAAAAAAAAAAAAbj6"
         "Ft+rmsoWtrMCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp160r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQD/////////////////////f////zAsBBT/////"
         "////////////////f////AQUHJe+/FS9eotlrPifgdTUrcVl+kUEKQRKlrVojvVz"
         "KEZkaYlow4u5E8v8giOmKFUxaJR9WdzJEgQjUTd6xfsyAhUBAAAAAAAAAAAAAfTI"
         "+Seu08p1IlcCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp160r2")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQD////////////////////+//+sczAsBBT/////"
         "///////////////+//+scAQUtOE00/tZ64urVydJBGZNWvUDiLoEKQRS3LA0KToR"
         "fh9P8Rsw9xmdMUTObf6v/vLjMfKW4HH6DfmYLP6n1D8uAhUBAAAAAAAAAAAAADUe"
         "54aoGPOhoWsCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp192k1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD//////////////////////////v//7jcwNAQY"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         "AAMEMQTbT/EOwFfpriawfQKAt/Q0HaXRsergbH2bLy9tnFYop4RBY9AVvoY0QIKq"
         "iNleL50CGQD///////////////4m8vwXD2lGanTe/Y0CAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp192r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
         "/////////////////////v/////////8BBhkIQUZ5ZyA5w+n6atyJDBJ/rje7MFG"
         "ubEEMQQYjagOsDCQ9ny/IOtDoYgA9P8K/YL/EBIHGSuV/8jaeGMQEe1rJM3Vc/l3"
         "oR55SBECGQD///////////////+Z3vg2FGvJsbTSKDECAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp224k1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHIAgEBMCgGByqGSM49AQECHQD///////////////////////////////7//+Vt"
         "MDwEHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEHAAAAAAAAAAAAAAAAAAA"
         "AAAAAAAAAAAAAAAAAAUEOQShRVszTfCZ3zD8KKFppGfp5HB1qQ9+ZQ62t6Rcfgif"
         "7X+6NEKCyvvW9+MZ98CwvVniykvbVW1hpQIdAQAAAAAAAAAAAAAAAAAB3OjS7GGE"
         "yvCpcXafsfcCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp224r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHIAgEBMCgGByqGSM49AQECHQD/////////////////////AAAAAAAAAAAAAAAB"
         "MDwEHP////////////////////7///////////////4EHLQFCoUMBLOr9UEyVlBE"
         "sLfXv9i6Jws5QyNV/7QEOQS3Dgy9a7S/fzITkLlKA8HTVsIRIjQygNYRXB0hvTdj"
         "iLX3I/tMIt/mzUN1oFoHR2RE1YGZhQB+NAIdAP//////////////////FqLguPA+"
         "E90pRVxcKj0CAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp256k1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+"
         "///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAA"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv8"
         "2y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA"
         "/////////////////////rqu3OavSKA7v9JejNA2QUECAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp256r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//////////"
         "/////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6"
         "k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9"
         "gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA"
         "/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE="
         "-----END EC PARAMETERS-----";

   if(name == "secp384r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIIBQAIBATA8BgcqhkjOPQEBAjEA////////////////////////////////////"
         "//////7/////AAAAAAAAAAD/////MGQEMP//////////////////////////////"
         "///////////+/////wAAAAAAAAAA/////AQwszEvp+I+5+SYjgVr4/gtGRgdnG7+"
         "gUESAxQIj1ATh1rGVjmNii7RnSqFyO3T7CrvBGEEqofKIr6LBTeOscce8yCtdG4d"
         "O2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0"
         "Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5fAjEA////////////////////"
         "////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlzAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "secp521r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIIBrAIBATBNBgcqhkjOPQEBAkIB////////////////////////////////////"
         "//////////////////////////////////////////////////8wgYgEQgH/////"
         "////////////////////////////////////////////////////////////////"
         "/////////////////ARCAFGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ"
         "4VYZOVHsfpN7FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8ABIGFBADGhY4GtwQE6c2e"
         "PstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5"
         "fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQm"
         "QMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////"
         "////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "brainpool160r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGYAgEBMCAGByqGSM49AQECFQDpXkpfc3BZ3GDfx62Vs9gTlRViDzAsBBQ0Dnvi"
         "ooDrdOK+YbradF2X6PfDAAQUHliahZVCNBITT6otveyVyNhnXlgEKQS+1a8W6j9q"
         "T2KTjEYx61r3vbzbwxZny0d6Go7DOPlHQWacl2MW2mMhAhUA6V5KX3NwWdxg31mR"
         "1FApQJ5g/AkCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "brainpool192r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQDDAvQdkyo2zaejRjCT0Y23j85HbeGoYpcwNAQY"
         "apEXQHax4OGcOcAx/oaFwcrgQOXGmijvBBhGmijvfCjMo9xyHQRPRJa8yn70FG+/"
         "JckEMQTAoGR+qrakh1OwM8VssPCQCi9cSFM3X9YUtpCGar1buItfSCjBSQAC5nc/"
         "ovopm48CGQDDAvQdkyo2zaejRi+enpFrW+jxAprErMECAQE="
         "-----END EC PARAMETERS-----";

   if(name == "brainpool224r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHIAgEBMCgGByqGSM49AQECHQDXwTSqJkNmhioYMCV10deHsJ8HV5faifV+yMD/"
         "MDwEHGil5iypzmwcKZgDpsFTC1FOGCrYsAQqWcrSn0MEHCWA9jzP5EE4hwcTsakj"
         "aeM+ITXSZtuzcjhsQAsEOQQNkCmtLH5c9DQII7KofcaMnkzjF0webv3uEsB9WKpW"
         "93LAcm8kxrieTs2sJDVLnpnKo/bTdhQCzQIdANfBNKomQ2aGKhgwJXXQ+5jRFrxL"
         "bd68o6Wnk58CAQE="
         "-----END EC PARAMETERS-----";

   if(name == "brainpool256r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQCp+1fboe6pvD5mCpCdg41ybjv2I9UmICggE0gd"
         "H25TdzBEBCB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12QQgJtxcbOlK"
         "S0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7YEQQSL0q65y35XyyxLSC/8gbevud4n"
         "4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXAiEA"
         "qftX26Huqbw+ZgqQnYONcYw5eqO1Yab3kB4OgpdIVqcCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "brainpool320r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIIBEAIBATA0BgcqhkjOPQEBAikA015HIDa8T7fhPHhe0gHgZfmPz6b29A3vT5K5"
         "7HiT7Cj81BKx8bMuJzBUBCg+4wtWj7qw+IPM69RtPzu4oqc1E/XredpmGQ6whf+p"
         "9JLzdal9hg60BChSCIOUnf28QtOtGYZAaIpv4T9BNJVUtJrMMdzNiEU5gW9etKyP"
         "sfGmBFEEQ71+mvtT2LhSibzEjuW/5vIBN9EKCH6254ceKhClmccQr40NOeIGERT9"
         "0FVF7BzIq0CTJH93J14HQ//tEXGC6qnHeHeqrGrH01JF0WkujuECKQDTXkcgNrxP"
         "t+E8eF7SAeBl+Y/PpbaPEqMtSC7H7oZY6YaRVVtExZMRAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "brainpool384r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIIBQAIBATA8BgcqhkjOPQEBAjEAjLkegqM4bSgPXW9+UOZB3xUvcQntVFa0ErHa"
         "GX+3ESOs06cpkB0acYdHABMxB+xTMGQEMHvDgsY9jBUMPHIICs4Fr6DCvqKOT7In"
         "hxORZe+6kfkPiqWBSlA61OsEqMfdIs4oJgQwBKjH3SLOKCaLObVUFvBEfC+3feEH"
         "3NKmLogOpT7rYtV8tDkCldvJlDq3hpb6UEwRBGEEHRxk8GjPRf+ipjqBt8E/a4hH"
         "o+d+8U/j23/K/gy9EOjoJuA0NtZGqu+HsuJH1K8eir4ddSD5wqRcseuOlc/VUmK3"
         "Cyn+7Fhk4ZwFT/mRKSgORkYhd5GBEUKCA0EmPFMVAjEAjLkegqM4bSgPXW9+UOZB"
         "3xUvcQntVFazHxZubKwEJafPOrava3/DEDuIMgLpBGVlAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "brainpool512r1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIIBogIBATBMBgcqhkjOPQEBAkEAqt2duNvpxIs/1OauM8n8B8swjbOzydIO1mOc"
         "ynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2CxoUoqmBWWDpI8zCBhARAeDCjMYtg"
         "O4niMnFFrCNMxZTL3Y09+RYQqDRByuqYY7wt7V1aqCU6oQou8cmLmsi1fxEXpyvy"
         "x7nnwaxNd/yUygRAPfkWEKg0QcrqmGO8Le1dWqglOqEKLvHJi5rItX8RF6cr8se5"
         "58GsTXf8lMrcCD5nmEBQt1665d0oCb1jgBb3IwSBgQSBruS92C7ZZFohMi6cTGqT"
         "he2fcLXZFsG0O2Lu9NAJjv87H3ji0NSNUNFoe5O5fV98bVBHQGpeaIs1Igm8ufgi"
         "fd44XVZjMuzA6r+pz3gi/fIJ9wAkpXsaoADFW4gfgRGy3N5JSl9IXlvKS9iKJ2Ou"
         "0corL6jwVAZ4zR4POtgIkgJBAKrdnbjb6cSLP9TmrjPJ/AfLMI2zs8nSDtZjnMpw"
         "MwhwVT5cQUypJhlBhmEZf6wQRx2x04EIXdrdtYeWgpypAGkCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "x962_p192v2")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
         "/////////////////////v/////////8BBjMItbfuVxrJeScDWNkpOWYDDk6ohZo"
         "2VMEMQTuorrn4Ul4QvLed2nP6cmJwHKtaW9IA0pldNEdabbsemcruCoIPfLysIR9"
         "6XCy3hUCGQD///////////////5fsack3IBBhkjY3TECAQE="
         "-----END EC PARAMETERS-----";

   if(name == "x962_p192v3")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
         "/////////////////////v/////////8BBgiEj3COVoFyqdCPa7MyUdgp9RiJWvV"
         "aRYEMQR9KXeBAMZaHaF4NxZYjc4ri0rujiKPGJY4qQ8iY3M3M0tJ3LZqbcj5l4rK"
         "dkipQ7ACGQD///////////////96YtAxyD9ClPZA7BMCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "x962_p239v1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
         "/zBABB5///////////////9///////+AAAAAAAB///////wEHmsBbDvc8YlB0NZU"
         "khR1ynGp2y+yfR03eWGFwpQsCgQ9BA/6ljzcqIFszDO4ZCvt+QXD01hXPT8n+707"
         "PLmqr33r6OTpCl2ubkBUylMLoEZUs2gYziJrOfzLewLxrgIef///////////////"
         "f///nl6an12QcfvRUiaIkJ0LAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "x962_p239v2")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
         "/zBABB5///////////////9///////+AAAAAAAB///////wEHmF/q2gyV2y7/tUN"
         "mfAknD/uWLlLoAOMeuhMjIMvLAQ9BDivCdmHJ3BRIMkhu16eJilqPNzy81dXoOr9"
         "h7gw51sBJeTb6g7HIG2g/AHZsIEyn7VV3m70YCN9/4vkugIef///////////////"
         "gAAAz6foWUN31BTAOCG8WCBjAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "x962_p239v3")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
         "/zBABB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZUsfTL"
         "A9anUKMMJQEC1JiHF9m6FattPgQ9BGdoro4Yu5LPzwBclJqixtlIU9DmYLv4VLHJ"
         "UF/pWhYH5omPOQwGvB1VK60ibztvz+SLboGEma8Y4+1s8wIef///////////////"
         "f///l13rQbOmBXw8QyFGUmVRAgEB"
         "-----END EC PARAMETERS-----";

   if(name == "gost_256A")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD/////////////////////////////////////"
         "///9lzBEBCD////////////////////////////////////////9lAQgAAAAAAAA"
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKYEQQQAAAAAAAAAAAAAAAAAAAAAAAAA"
         "AAAAAAAAAAAAAAAAAY2R5HHgmJzaJ99QWkU/K3Y1KU8t3yPjsSKsyZyenx4UAiEA"
         "/////////////////////2xhEHCZWtEARYQbCbdhuJMCAQE="
         "-----END EC PARAMETERS-----";

   if(name == "frp256v1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQDx/ReMCzrVjxASbejOQkNbOWGtvKvIym3o/PNT"
         "2G6cAzBEBCDx/ReMCzrVjxASbejOQkNbOWGtvKvIym3o/PNT2G6cAAQg7jU/ylQo"
         "qTANSrp1SkTAD9/sDJrksaGAMHXtlnt7tz8EQQS2s9TDVsE56zEYPUdJ1COVjCfS"
         "3K+YtwFkyXot2Y9c/2FC4PfIsgSRH5Jx8PPs74wnAcMH6OTJ4YMRWhVUBiz7AiEA"
         "8f0XjAs61Y8QEm3ozkJDW1PcZ+FA0r+UH/3UWcbWVeECAQE="
         "-----END EC PARAMETERS-----";

   if(name == "sm2p256v1")
      return
         "-----BEGIN EC PARAMETERS-----"
         "MIHgAgEBMCwGByqGSM49AQECIQD////+/////////////////////wAAAAD/////"
         "/////zBEBCD////+/////////////////////wAAAAD//////////AQgKOn6np2f"
         "XjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+ML"
         "v/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA"
         "/////v///////////////3ID32shxgUrU7v0CTnVQSMCAQE="
         "-----END EC PARAMETERS-----";

#if defined(BOTAN_HOUSE_ECC_CURVE_NAME)
   if(name == BOTAN_HOUSE_ECC_CURVE_NAME)
      return BOTAN_HOUSE_ECC_CURVE_PEM;
#endif

   return "";
   }

}
