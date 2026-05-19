/*
* SQL database interface
* (C) 2014,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SQL_DATABASE_H_
#define BOTAN_SQL_DATABASE_H_

#include <botan/exceptn.h>
#include <botan/types.h>
#include <chrono>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Botan {

class BOTAN_PUBLIC_API(2, 0) SQL_Database /* NOLINT(*-special-member-functions) */ {
   public:
      class BOTAN_PUBLIC_API(2, 0) SQL_DB_Error final : public Exception {
         public:
            explicit SQL_DB_Error(std::string_view what) : Exception("SQL database", what), m_rc(0) {}

            SQL_DB_Error(std::string_view what, int rc) : Exception("SQL database", what), m_rc(rc) {}

            ErrorType error_type() const noexcept override { return ErrorType::DatabaseError; }

            int error_code() const noexcept override { return m_rc; }

         private:
            int m_rc;
      };

      class BOTAN_PUBLIC_API(2, 0) Statement /* NOLINT(*-special-member-functions) */ {
         public:
            /* Bind statement parameters */
            virtual void bind(int column, std::string_view str) = 0;

            virtual void bind(int column, size_t i) = 0;

            virtual void bind(int column, std::chrono::system_clock::time_point time) = 0;

            virtual void bind(int column, const std::vector<uint8_t>& blob) = 0;

            virtual void bind(int column, const uint8_t* data, size_t len) = 0;

            virtual void bind_null(int column) = 0;

            /* Get blob output */
            virtual std::span<const uint8_t> get_blob(int column) = 0;

            /* Get string output, returns nullopt if the column value was NULL */
            virtual std::optional<std::string> get_str(int column) = 0;

            virtual size_t get_size_t(int column) = 0;

            /* Run to completion */
            virtual size_t spin() = 0;

            /* Maybe update */
            virtual bool step() = 0;

            virtual ~Statement() = default;
      };

      /*
      * Create a new statement for execution.
      * Use ?1, ?2, ?3, etc for parameters to set later with bind
      */
      virtual std::shared_ptr<Statement> new_statement(std::string_view base_sql) const = 0;

      /*
      * Prepare a "SELECT <columns> FROM <table> [WHERE <where>] [LIMIT <limit>]"
      * statement. `where` is the body of the WHERE clause (e.g.
      * "id = ?1 AND name = ?2"); pass an empty string for no WHERE clause. Use
      * ?1, ?2, ... for bound parameters. Virtual so backends can override if helpful.
      */
      virtual std::shared_ptr<Statement> select(std::string_view columns,
                                                std::string_view table,
                                                std::string_view where = {},
                                                std::optional<size_t> limit = std::nullopt) const;

      /*
      * Prepare an upsert (insert-or-replace) statement for the given columns of
      * the given table. The returned statement expects placeholders ?1..?N
      * bound in the order the columns were given. The list must include every
      * column of the table's primary key; backends that need the key/value
      * distinction (e.g. Postgres ON CONFLICT) derive it by introspecting the
      * schema.
      */
      virtual std::shared_ptr<Statement> upsert(std::string_view table,
                                                std::initializer_list<std::string_view> columns) const = 0;

      virtual size_t row_count(std::string_view table_name) = 0;

      enum class Column_Type : uint8_t {
         Blob,
         String,
         Integer,
      };

      class Column {
         public:
            Column(std::string name, Column_Type type) : m_name(std::move(name)), m_type(type) {}

            Column& primary_key() {
               m_primary_key = true;
               return *this;
            }

            Column& not_null() {
               m_not_null = true;
               return *this;
            }

            Column& unique() {
               m_unique = true;
               return *this;
            }

            const std::string& name() const { return m_name; }

            Column_Type type() const { return m_type; }

            bool is_primary_key() const { return m_primary_key; }

            bool is_not_null() const { return m_not_null; }

            bool is_unique() const { return m_unique; }

         private:
            std::string m_name;
            Column_Type m_type;
            bool m_primary_key = false;
            bool m_not_null = false;
            bool m_unique = false;
      };

      class Table_Schema {
         public:
            Table_Schema(std::string name, std::vector<Column> columns) :
                  m_name(std::move(name)), m_columns(std::move(columns)) {}

            Table_Schema& if_not_exists() {
               m_if_not_exists = true;
               return *this;
            }

            const std::string& name() const { return m_name; }

            const std::vector<Column>& columns() const { return m_columns; }

            bool is_if_not_exists() const { return m_if_not_exists; }

         private:
            std::string m_name;
            std::vector<Column> m_columns;
            bool m_if_not_exists = false;
      };

      virtual void create_table(const Table_Schema& schema) = 0;

      virtual size_t rows_changed_by_last_statement() = 0;

      virtual size_t exec(std::string_view sql) { return new_statement(sql)->spin(); }

      virtual bool is_threadsafe() const { return false; }

      virtual ~SQL_Database() = default;
};

}  // namespace Botan

#endif
