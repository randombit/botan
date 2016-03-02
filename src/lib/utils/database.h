/*
* SQL database interface
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SQL_DATABASE_H__
#define BOTAN_SQL_DATABASE_H__

#include <botan/types.h>
#include <botan/exceptn.h>
#include <string>
#include <chrono>
#include <vector>

namespace Botan {

class BOTAN_DLL SQL_Database
   {
   public:

      class BOTAN_DLL SQL_DB_Error : public Exception
         {
         public:
            explicit SQL_DB_Error(const std::string& what) : Exception("SQL database", what) {}
         };

      class BOTAN_DLL Statement
         {
         public:
            /* Bind statement parameters */
            virtual void bind(int column, const std::string& str) = 0;

            virtual void bind(int column, size_t i) = 0;

            virtual void bind(int column, std::chrono::system_clock::time_point time) = 0;

            virtual void bind(int column, const std::vector<byte>& blob) = 0;

            /* Get output */
            virtual std::pair<const byte*, size_t> get_blob(int column) = 0;

            virtual size_t get_size_t(int column) = 0;

            /* Run to completion */
            virtual size_t spin() = 0;

            /* Maybe update */
            virtual bool step() = 0;

            virtual ~Statement() {}
         };

      /*
      * Create a new statement for execution.
      * Use ?1, ?2, ?3, etc for parameters to set later with bind
      */
      virtual std::shared_ptr<Statement> new_statement(const std::string& base_sql) const = 0;

      virtual size_t row_count(const std::string& table_name) = 0;

      virtual void create_table(const std::string& table_schema) = 0;

      virtual ~SQL_Database() {}
};

}

#endif
