
#include <iostream>
#include <iomanip>
#include <ctime>
#include <cmath>
#include <string>
#include <exception>

#include <botan/rng.h>
#include <botan/filters.h>
using namespace Botan_types;

#include "common.h"

/* Discard output to reduce overhead */
struct BitBucket : public Botan::Filter
   {
   void write(const byte[], u32bit) {}
   };

Botan::Filter* lookup(const std::string&,
                      const std::vector<std::string>&,
                      const std::string& = "All");

double bench_filter(std::string name, Botan::Filter* filter,
                    bool html, double seconds)
   {
   Botan::Pipe pipe(filter, new BitBucket);
   pipe.start_msg();

   static const u32bit BUFFERSIZE = 32*1024;
   byte buf[BUFFERSIZE];

   Botan::Global_RNG::randomize(buf, BUFFERSIZE);

   u32bit iterations = 0;
   std::clock_t start = std::clock(), clocks_used = 0;

   while(clocks_used < seconds * CLOCKS_PER_SEC)
      {
      iterations++;
      pipe.write(buf, BUFFERSIZE);
      clocks_used = std::clock() - start;
      }

   double bytes_per_sec = ((double)iterations * BUFFERSIZE) /
                          ((double)clocks_used / CLOCKS_PER_SEC);
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
      std::cout << mbytes_per_sec << " Mbytes/sec" << std::endl;
      }
   return (mbytes_per_sec);
   }

double bench(const std::string& name, const std::string& filtername, bool html,
             double seconds, u32bit keylen, u32bit ivlen)
   {
   std::vector<std::string> params;

   params.push_back(std::string(int(2*keylen), 'A'));
   params.push_back(std::string(int(2* ivlen), 'A'));

   Botan::Filter* filter = lookup(filtername, params);

   if(filter)
      return bench_filter(name, filter, html, seconds);
   return 0;
   }

void benchmark(const std::string& what, bool html, double seconds)
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
                   << "<TH>Mbytes / second\n"
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
                                 algos[j].ivlen);
            if(speed > .00001) /* log(0) == -inf -> messed up average */
               sum += std::log(speed);
            how_many++;
            }

      if(html)
         std::cout << "</TABLE>\n\n";

      double average = std::exp(sum / (double)how_many);

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

u32bit bench_algo(const std::string& name, double seconds)
   {
   try {
      std::vector<algorithm> algos = get_algos();

      for(u32bit j = 0; j != algos.size(); j++)
         {
         if(algos[j].name == name)
            {
            bench(algos[j].name, algos[j].filtername, false, seconds,
                  algos[j].keylen, algos[j].ivlen);
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
