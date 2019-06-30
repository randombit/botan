/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "argparse.h"
#include <botan/rng.h>
#include <botan/parsing.h>
#include <botan/internal/os_utils.h>
#include <iostream>
#include <fstream>

#if defined(BOTAN_HAS_HEX_CODEC)
   #include <botan/hex.h>
#endif

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_BASE58_CODEC)
   #include <botan/base58.h>
#endif

namespace Botan_CLI {

Command::Command(const std::string& cmd_spec) : m_spec(cmd_spec)
   {
   // for checking all spec strings at load time
   //m_args.reset(new Argument_Parser(m_spec));
   }

Command::~Command() { /* for unique_ptr */ }

std::string Command::cmd_name() const
   {
   return m_spec.substr(0, m_spec.find(' '));
   }

std::string Command::help_text() const
   {
   return "Usage: " + m_spec;
   }

int Command::run(const std::vector<std::string>& params)
   {
   try
      {
      m_args.reset(new Argument_Parser(m_spec,
                                       {"verbose", "help"},
                                       {"output", "error-output", "rng-type", "drbg-seed"}));

      m_args->parse_args(params);

      if(m_args->has_arg("output"))
         {
         const std::string output_file = get_arg("output");

         if(output_file != "")
            {
            m_output_stream.reset(new std::ofstream(output_file, std::ios::binary));
            if(!m_output_stream->good())
               throw CLI_IO_Error("opening", output_file);
            }
         }

      if(m_args->has_arg("error-output"))
         {
         const std::string output_file = get_arg("error-output");

         if(output_file != "")
            {
            m_error_output_stream.reset(new std::ofstream(output_file, std::ios::binary));
            if(!m_error_output_stream->good())
               throw CLI_IO_Error("opening", output_file);
            }
         }

      if(flag_set("help"))
         {
         output() << help_text() << "\n";
         return 2;
         }

      this->go();
      return m_return_code;
      }
   catch(CLI_Usage_Error& e)
      {
      error_output() << "Usage error: " << e.what() << "\n";
      error_output() << help_text() << "\n";
      return 1;
      }
   catch(std::exception& e)
      {
      error_output() << "Error: " << e.what() << "\n";
      return 2;
      }
   catch(...)
      {
      error_output() << "Error: unknown exception\n";
      return 2;
      }
   }

bool Command::flag_set(const std::string& flag_name) const
   {
   return m_args->flag_set(flag_name);
   }

std::string Command::get_arg(const std::string& opt_name) const
   {
   return m_args->get_arg(opt_name);
   }

/*
* Like get_arg() but if the argument was not specified or is empty, returns otherwise
*/
std::string Command::get_arg_or(const std::string& opt_name, const std::string& otherwise) const
   {
   return m_args->get_arg_or(opt_name, otherwise);
   }

size_t Command::get_arg_sz(const std::string& opt_name) const
   {
   return m_args->get_arg_sz(opt_name);
   }

uint16_t Command::get_arg_u16(const std::string& opt_name) const
   {
   const size_t val = get_arg_sz(opt_name);
   if(static_cast<uint16_t>(val) != val)
      throw CLI_Usage_Error("Argument " + opt_name + " has value out of allowed range");
   return static_cast<uint16_t>(val);
   }

uint32_t Command::get_arg_u32(const std::string& opt_name) const
   {
   const size_t val = get_arg_sz(opt_name);
   if(static_cast<uint32_t>(val) != val)
      throw CLI_Usage_Error("Argument " + opt_name + " has value out of allowed range");
   return static_cast<uint32_t>(val);
   }

std::vector<std::string> Command::get_arg_list(const std::string& what) const
   {
   return m_args->get_arg_list(what);
   }

std::ostream& Command::output()
   {
   if(m_output_stream.get())
      {
      return *m_output_stream;
      }
   return std::cout;
   }

std::ostream& Command::error_output()
   {
   if(m_error_output_stream.get())
      {
      return *m_error_output_stream;
      }
   return std::cerr;
   }

std::vector<uint8_t> Command::slurp_file(const std::string& input_file,
                                         size_t buf_size) const
   {
   std::vector<uint8_t> buf;
   auto insert_fn = [&](const uint8_t b[], size_t l)
      {
      buf.insert(buf.end(), b, b + l);
      };
   this->read_file(input_file, insert_fn, buf_size);
   return buf;
   }

std::string Command::slurp_file_as_str(const std::string& input_file,
                                       size_t buf_size) const
   {
   std::string str;
   auto insert_fn = [&](const uint8_t b[], size_t l)
      {
      str.append(reinterpret_cast<const char*>(b), l);
      };
   this->read_file(input_file, insert_fn, buf_size);
   return str;
   }

void Command::read_file(const std::string& input_file,
                        std::function<void (uint8_t[], size_t)> consumer_fn,
                        size_t buf_size) const
   {
   if(input_file == "-")
      {
      do_read_file(std::cin, consumer_fn, buf_size);
      }
   else
      {
      std::ifstream in(input_file, std::ios::binary);
      if(!in)
         {
         throw CLI_IO_Error("reading file", input_file);
         }
      do_read_file(in, consumer_fn, buf_size);
      }
   }

void Command::do_read_file(std::istream& in,
                           std::function<void (uint8_t[], size_t)> consumer_fn,
                           size_t buf_size) const
   {
   // Avoid an infinite loop on --buf-size=0
   std::vector<uint8_t> buf(buf_size == 0 ? 4096 : buf_size);

   while(in.good())
      {
      in.read(reinterpret_cast<char*>(buf.data()), buf.size());
      const size_t got = static_cast<size_t>(in.gcount());
      consumer_fn(buf.data(), got);
      }
   }

Botan::RandomNumberGenerator& Command::rng()
   {
   if(m_rng == nullptr)
      {
      m_rng = cli_make_rng(get_arg("rng-type"), get_arg("drbg-seed"));
      }

   return *m_rng.get();
   }

std::string Command::get_passphrase_arg(const std::string& prompt, const std::string& opt_name)
   {
   const std::string s = get_arg(opt_name);
   if(s != "-")
      return s;
   return get_passphrase(prompt);
   }

namespace {

bool echo_suppression_supported()
   {
   auto echo = Botan::OS::suppress_echo_on_terminal();
   return (echo != nullptr);
   }

}

std::string Command::get_passphrase(const std::string& prompt)
   {
   if(echo_suppression_supported() == false)
      error_output() << "Warning: terminal echo suppression not enabled for this platform\n";

   error_output() << prompt << ": " << std::flush;
   std::string pass;

   auto echo_suppress = Botan::OS::suppress_echo_on_terminal();

   std::getline(std::cin, pass);

   return pass;
   }

//static
std::string Command::format_blob(const std::string& format,
                                 const uint8_t bits[], size_t len)
   {
#if defined(BOTAN_HAS_HEX_CODEC)
   if(format == "hex")
      {
      return Botan::hex_encode(bits, len);
      }
#endif

#if defined(BOTAN_HAS_BASE64_CODEC)
   if(format == "base64")
      {
      return Botan::base64_encode(bits, len);
      }
#endif

#if defined(BOTAN_HAS_BASE58_CODEC)
   if(format == "base58")
      {
      return Botan::base58_encode(bits, len);
      }
   if(format == "base58check")
      {
      return Botan::base58_check_encode(bits, len);
      }
#endif

   // If we supported format, we would have already returned
   throw CLI_Usage_Error("Unknown or unsupported format type");
   }

// Registration code

Command::Registration::Registration(const std::string& name, Command::cmd_maker_fn maker_fn)
   {
   std::map<std::string, Command::cmd_maker_fn>& reg = Command::global_registry();

   if(reg.count(name) > 0)
      {
      throw CLI_Error("Duplicated registration of command " + name);
      }

   reg.insert(std::make_pair(name, maker_fn));
   }

//static
std::map<std::string, Command::cmd_maker_fn>& Command::global_registry()
   {
   static std::map<std::string, Command::cmd_maker_fn> g_cmds;
   return g_cmds;
   }

//static
std::vector<std::string> Command::registered_cmds()
   {
   std::vector<std::string> cmds;
   for(auto& cmd : Command::global_registry())
      cmds.push_back(cmd.first);
   return cmds;
   }

//static
std::unique_ptr<Command> Command::get_cmd(const std::string& name)
   {
   const std::map<std::string, Command::cmd_maker_fn>& reg = Command::global_registry();

   std::unique_ptr<Command> r;
   auto i = reg.find(name);
   if(i != reg.end())
      {
      r.reset(i->second());
      }

   return r;
   }

}
