
#include <iostream>
#include <iomanip>
#include <cmath>
#include <string>
#include <exception>

#include <botan/filters.h>
using Botan::byte;
using Botan::u64bit;

#include "common.h"
#include "timer.h"
#include "bench.h"

/* Discard output to reduce overhead */
struct BitBucket : public Botan::Filter
   {
   void write(const byte[], u32bit) {}
   };

Botan::Filter* lookup(const std::string&,
                      const std::vector<std::string>&,
                      const std::string& = "All");

namespace {

double bench_filter(std::string name, Botan::Filter* filter,
                    Botan::RandomNumberGenerator& rng,
                    bool html, double seconds)
   {
   Botan::Pipe pipe(filter, new BitBucket);

   std::vector<byte> buf(128 * 1024);
   rng.randomize(&buf[0], buf.size());

   pipe.start_msg();

   Timer timer(name, buf.size());

   while(timer.seconds() < seconds)
      {
      timer.start();
      pipe.write(&buf[0], buf.size());
      timer.stop();
      }

   pipe.end_msg();

   double bytes_per_sec = timer.events() / timer.seconds();
   double mbytes_per_sec = bytes_per_sec / (1024.0 * 1024.0);

   std::cout.setf(std::ios::fixed, std::ios::floatfield);
   std::cout.precision(2);
   if(html)
      {
      if(name.find("<") != std::string::npos)
         name.replace(name.find("<"), 1, "&lt;");
      if(name.find(">") != std::string::npos)
         name.replace(name.find(">"), 1, "&gt;");
      std::cout << "   <TR><TH>" << name
                << std::string(25 - name.length(), ' ') << "   <TH>";
      std::cout.width(6);
      std::cout << mbytes_per_sec << std::endl;
      }
   else
      {
      std::cout << name << ": " << std::string(25 - name.length(), ' ');
      std::cout.width(6);
      std::cout << mbytes_per_sec << " MiB/sec" << std::endl;
      }
   return (mbytes_per_sec);
   }

double bench(const std::string& name, const std::string& filtername, bool html,
             double seconds, u32bit keylen, u32bit ivlen,
             Botan::RandomNumberGenerator& rng)
   {
   std::vector<std::string> params;

   Botan::SecureVector<byte> key(keylen);
   rng.randomize(key, key.size());
   params.push_back(hex_encode(key, key.size()));

   //params.push_back(std::string(int(2*keylen), 'A'));
   params.push_back(std::string(int(2* ivlen), 'A'));

   Botan::Filter* filter = lookup(filtername, params);

   if(filter)
      return bench_filter(name, filter, rng, html, seconds);
   return 0;
   }

}

void benchmark(const std::string& what,
               Botan::RandomNumberGenerator& rng,
               bool html, double seconds)
   {
   try {
      if(html)
         {
         std::cout << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD "
                   << "HTML 4.0 Transitional//EN\">\n"
                   << "<HTML>\n\n"
                   << "<TITLE>Botan Benchmarks</TITLE>\n\n"
                   << "<BODY>\n\n"
                   << "<P><TABLE BORDER CELLSPACING=1>\n"
                   << "<THEAD>\n"
                   << "<TR><TH>Algorithm                      "
                   << "<TH>Mib / second\n"
                   << "<TBODY>\n";
         }

      double sum = 0;
      u32bit how_many = 0;

      std::vector<algorithm> algos = get_algos();

      for(u32bit j = 0; j != algos.size(); j++)
         if(what == "All" || what == algos[j].type)
            {
            double speed = bench(algos[j].name, algos[j].filtername,
                                 html, seconds, algos[j].keylen,
                                 algos[j].ivlen, rng);
            if(speed > .00001) /* log(0) == -inf -> messed up average */
               sum += std::log(speed);
            how_many++;
            }

      if(html)
         std::cout << "</TABLE>\n\n";

      double average = std::exp(sum / static_cast<double>(how_many));

      if(what == "All" && html)
         std::cout << "\n<P>Overall speed average: " << average
                   << "\n\n";
      else if(what == "All")
          std::cout << "\nOverall speed average: " << average
                    << std::endl;

      if(html) std::cout << "</BODY></HTML>\n";
      }
   catch(Botan::Exception& e)
      {
      std::cout << "Botan exception caught: " << e.what() << std::endl;
      return;
      }
   catch(std::exception& e)
      {
      std::cout << "Standard library exception caught: " << e.what()
                << std::endl;
      return;
      }
   catch(...)
      {
      std::cout << "Unknown exception caught." << std::endl;
      return;
      }
   }

u32bit bench_algo(const std::string& name,
                  Botan::RandomNumberGenerator& rng,
                  double seconds)
   {
   try {
      std::vector<algorithm> algos = get_algos();

      for(u32bit j = 0; j != algos.size(); j++)
         {
         if(algos[j].name == name)
            {
            bench(algos[j].name, algos[j].filtername, false, seconds,
                  algos[j].keylen, algos[j].ivlen, rng);
            return 1;
            }
         }
      return 0;
      }
   catch(Botan::Exception& e)
      {
      std::cout << "Botan exception caught: " << e.what() << std::endl;
      return 0;
      }
   catch(std::exception& e)
      {
      std::cout << "Standard library exception caught: " << e.what()
                << std::endl;
      return 0;
      }
   catch(...)
      {
      std::cout << "Unknown exception caught." << std::endl;
      return 0;
      }
   }
