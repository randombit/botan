/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_H_
#define BOTAN_CLI_H_

#include "cli_exceptions.h"
#include <botan/types.h>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

}

namespace Botan_CLI {

class Argument_Parser;

/* Declared in cli_rng.cpp */
std::shared_ptr<Botan::RandomNumberGenerator> cli_make_rng(const std::string& type = "",
                                                           const std::string& hex_drbg_seed = "");

class Command {
   public:
      /**
      * Get a registered command
      */
      static std::unique_ptr<Command> get_cmd(const std::string& name);

      static std::vector<std::string> registered_cmds();

      /**
      * The spec string specifies the format of the command line, eg for
      * a somewhat complicated command:
      * cmd_name --flag --option1= --option2=opt2val input1 input2 *rest
      *
      * By default this is the value returned by help_text()
      *
      * The first value is always the command name. Options may appear
      * in any order. Named arguments are taken from the command line
      * in the order they appear in the spec.
      *
      * --flag can optionally be specified, and takes no value.
      * Check for it in go() with flag_set()
      *
      * --option1 is an option whose default value (if the option
      * does not appear on the command line) is the empty string.
      *
      * --option2 is an option whose default value is opt2val
      * Read the values in go() using get_arg or get_arg_sz.
      *
      * The values input1 and input2 specify named arguments which must
      * be provided. They are also access via get_arg/get_arg_sz
      * Because options and arguments for a single command share the same
      * namespace you can't have a spec like:
      *   cmd --input input
      * but you hopefully didn't want to do that anyway.
      *
      * The leading '*' on '*rest' specifies that all remaining arguments
      * should be packaged in a list which is available as get_arg_list("rest").
      * This can only appear on a single value and should be the final
      * named argument.
      *
      * Every command has implicit flags --help, --verbose and implicit
      * options --output= and --error-output= which override the default
      * use of std::cout and std::cerr.
      *
      * Use of --help is captured in run() and returns help_text().
      * Use of --verbose can be checked with verbose() or flag_set("verbose")
      */
      explicit Command(const std::string& cmd_spec);

      virtual ~Command();

      int run(const std::vector<std::string>& params);

      virtual std::string group() const = 0;

      virtual std::string description() const = 0;

      virtual std::string help_text() const;

      const std::string& cmd_spec() const { return m_spec; }

      std::string cmd_name() const;

      static std::vector<std::string> split_on(const std::string& str, char delim);

   protected:
      /*
      * The actual functionality of the cli command implemented in subclass.
      * The return value from main will be zero.
      */
      virtual void go() = 0;

      void set_return_code(int rc) { m_return_code = rc; }

      std::ostream& output();

      /**
       * @brief Returns a stream to output binary data too.
       *
       * Note: If output is set to stdout, it will be globally set to binary mode.
       * Avoid mixing outputting binary and text data in the same command.
       */
      std::ostream& output_binary();

      std::ostream& error_output();

      bool verbose() const { return flag_set("verbose"); }

      std::string get_passphrase(const std::string& prompt);

      bool flag_set(const std::string& flag_name) const;

      static std::string format_blob(const std::string& format, const uint8_t bits[], size_t len);

      template <typename Alloc>
      static std::string format_blob(const std::string& format, const std::vector<uint8_t, Alloc>& vec) {
         return format_blob(format, vec.data(), vec.size());
      }

      std::string get_arg(const std::string& opt_name) const;

      /**
      * Like get_arg but if the value is '-' then reads a passphrase from
      * the terminal with echo suppressed.
      */
      std::string get_passphrase_arg(const std::string& prompt, const std::string& opt_name);

      /*
      * Like get_arg() but if the argument was not specified or is empty, returns otherwise
      */
      std::string get_arg_or(const std::string& opt_name, const std::string& otherwise) const;

      /*
      * Like get_arg() but if the argument was not specified or is empty, returns std::nullopt
      */
      std::optional<std::string> get_arg_maybe(const std::string& opt_name) const;

      size_t get_arg_sz(const std::string& opt_name) const;

      uint16_t get_arg_u16(const std::string& opt_name) const;

      uint32_t get_arg_u32(const std::string& opt_name) const;

      std::vector<std::string> get_arg_list(const std::string& what) const;

      /*
      * Read an entire file into memory and return the contents
      */
      std::vector<uint8_t> slurp_file(const std::string& input_file, size_t buf_size = 0) const;

      std::string slurp_file_as_str(const std::string& input_file, size_t buf_size = 0) const;

      /*
      * Read a file calling consumer_fn() with the inputs
      */
      static void read_file(const std::string& input_file,
                            const std::function<void(uint8_t[], size_t)>& consumer_fn,
                            size_t buf_size = 0);

      static void do_read_file(std::istream& in,
                               const std::function<void(uint8_t[], size_t)>& consumer_fn,
                               size_t buf_size = 0);

      /**
       * @brief Write binary data to the configured output.
       *
       * Note: If output is set to stdout, it will be globally set to binary mode.
       * Avoid mixing outputting binary and text data in the same command.
       *
       * @param vec Data to write.
       */
      template <typename Alloc>
      void write_output(const std::vector<uint8_t, Alloc>& vec) {
         output_binary().write(reinterpret_cast<const char*>(vec.data()), vec.size());
      }

      Botan::RandomNumberGenerator& rng();
      std::shared_ptr<Botan::RandomNumberGenerator> rng_as_shared();

   private:
      typedef std::function<std::unique_ptr<Command>()> cmd_maker_fn;
      static std::map<std::string, cmd_maker_fn>& global_registry();

      void parse_spec();

      // set in constructor
      std::string m_spec;

      std::unique_ptr<Argument_Parser> m_args;
      std::unique_ptr<std::ostream> m_output_stream;
      std::unique_ptr<std::ostream> m_error_output_stream;

      std::shared_ptr<Botan::RandomNumberGenerator> m_rng;

      // possibly set by calling set_return_code()
      int m_return_code = 0;

   public:
      // the registry interface:

      class Registration final {
         public:
            Registration(const std::string& name, const cmd_maker_fn& maker_fn);
      };
};

#define BOTAN_REGISTER_COMMAND(name, CLI_Class)                \
   const Botan_CLI::Command::Registration reg_cmd_##CLI_Class( \
      name, []() -> std::unique_ptr<Botan_CLI::Command> { return std::make_unique<CLI_Class>(); })

}  // namespace Botan_CLI

#endif
