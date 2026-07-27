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

/**
* Abstract interface to a SQL database
*/
class BOTAN_PUBLIC_API(2, 0) SQL_Database /* NOLINT(*-special-member-functions) */ {
   public:
      /**
      * An error occurred while interacting with the database
      */
      class BOTAN_PUBLIC_API(2, 0) SQL_DB_Error final : public Exception {
         public:
            /**
            * Create a SQL_DB_Error
            * @param what a description of the failure
            */
            explicit SQL_DB_Error(std::string_view what) : Exception("SQL database", what), m_rc(0) {}

            /**
            * Create a SQL_DB_Error
            * @param what a description of the failure
            * @param rc the database specific result code
            */
            SQL_DB_Error(std::string_view what, int rc) : Exception("SQL database", what), m_rc(rc) {}

            /**
            * Return the error type of this exception
            * @return the error type of this exception
            */
            ErrorType error_type() const noexcept override { return ErrorType::DatabaseError; }

            /**
            * Return the database specific result code
            * @return the result code passed at construction, or 0
            */
            int error_code() const noexcept override { return m_rc; }

         private:
            int m_rc;
      };

      /**
      * A prepared SQL statement
      */
      class BOTAN_PUBLIC_API(2, 0) Statement /* NOLINT(*-special-member-functions) */ {
         public:
            /**
            * Bind a string to a statement parameter
            * @param column the 1-based index of the parameter
            * @param str the value to bind
            */
            virtual void bind(int column, std::string_view str) = 0;

            /**
            * Bind an integer to a statement parameter
            * @param column the 1-based index of the parameter
            * @param i the value to bind
            */
            virtual void bind(int column, size_t i) = 0;

            /**
            * Bind a timestamp to a statement parameter
            * @param column the 1-based index of the parameter
            * @param time the value to bind
            */
            virtual void bind(int column, std::chrono::system_clock::time_point time) = 0;

            /**
            * Bind a blob to a statement parameter
            * @param column the 1-based index of the parameter
            * @param blob the value to bind
            */
            virtual void bind(int column, const std::vector<uint8_t>& blob) = 0;

            /**
            * Bind a blob to a statement parameter
            * @param column the 1-based index of the parameter
            * @param data the value to bind
            * @param len length of data in bytes
            */
            virtual void bind(int column, const uint8_t* data, size_t len) = 0;

            /**
            * Bind SQL NULL to a statement parameter
            * @param column the 1-based index of the parameter
            */
            virtual void bind_null(int column) = 0;

            /**
            * Read a blob from the current result row
            * @param column the 0-based index of the column
            * @return the blob value, valid until the next call to step
            */
            virtual std::span<const uint8_t> get_blob(int column) = 0;

            /**
            * Read a string from the current result row
            * @param column the 0-based index of the column
            * @return the string value, or nullopt if the column value was NULL
            */
            virtual std::optional<std::string> get_str(int column) = 0;

            /**
            * Read an integer from the current result row
            * @param column the 0-based index of the column
            * @return the integer value
            */
            virtual size_t get_size_t(int column) = 0;

            /**
            * Run the statement to completion
            * @return the number of result rows which were stepped over
            */
            virtual size_t spin() = 0;

            /**
            * Advance to the next result row
            * @return true if a row is available, false once the results are exhausted
            */
            virtual bool step() = 0;

            virtual ~Statement() = default;
      };

      /**
      * Create a new statement for execution.
      * Use ?1, ?2, ?3, etc for parameters to set later with bind
      *
      * @param base_sql the SQL text of the statement
      * @return the prepared statement
      */
      virtual std::shared_ptr<Statement> new_statement(std::string_view base_sql) const = 0;

      /**
      * Prepare a "SELECT <columns> FROM <table> [WHERE <where>] [LIMIT <limit>]"
      * statement. `where` is the body of the WHERE clause (e.g.
      * "id = ?1 AND name = ?2"); pass an empty string for no WHERE clause. Use
      * ?1, ?2, ... for bound parameters. Virtual so backends can override if helpful.
      *
      * @param columns the columns to select
      * @param table the table to select from
      * @param where the body of the WHERE clause, or empty for no WHERE clause
      * @param limit the maximum number of rows, or nullopt for no limit
      * @return the prepared statement
      */
      virtual std::shared_ptr<Statement> select(std::string_view columns,
                                                std::string_view table,
                                                std::string_view where = {},
                                                std::optional<size_t> limit = std::nullopt) const;

      /**
      * Prepare an upsert (insert-or-replace) statement for the given columns of
      * the given table. The returned statement expects placeholders ?1..?N
      * bound in the order the columns were given. The list must include every
      * column of the table's primary key; backends that need the key/value
      * distinction (e.g. Postgres ON CONFLICT) derive it by introspecting the
      * schema.
      *
      * @param table the table to upsert into
      * @param columns the columns to write, in placeholder order
      * @return the prepared statement
      */
      virtual std::shared_ptr<Statement> upsert(std::string_view table,
                                                std::initializer_list<std::string_view> columns) const = 0;

      /**
      * Count the rows of a table
      * @param table_name the table to count
      * @return the number of rows in the table
      */
      virtual size_t row_count(std::string_view table_name) = 0;

      /**
      * The supported column types
      */
      enum class Column_Type : uint8_t {
         Blob,
         String,
         Integer,
      };

      /**
      * The name, type and constraints of one column of a table
      */
      class Column {
         public:
            /**
            * Declare a column
            * @param name the name of the column
            * @param type the type of the column
            */
            Column(std::string name, Column_Type type) : m_name(std::move(name)), m_type(type) {}

            /**
            * Mark this column as part of the primary key
            * @return reference to this
            */
            Column& primary_key() {
               m_primary_key = true;
               return *this;
            }

            /**
            * Mark this column as NOT NULL
            * @return reference to this
            */
            Column& not_null() {
               m_not_null = true;
               return *this;
            }

            /**
            * Mark this column as UNIQUE
            * @return reference to this
            */
            Column& unique() {
               m_unique = true;
               return *this;
            }

            /**
            * Query the column name
            * @return the name of the column
            */
            const std::string& name() const { return m_name; }

            /**
            * Query the column type
            * @return the type of the column
            */
            Column_Type type() const { return m_type; }

            /**
            * Query whether this column is part of the primary key
            * @return true if primary_key was called
            */
            bool is_primary_key() const { return m_primary_key; }

            /**
            * Query whether this column is NOT NULL
            * @return true if not_null was called
            */
            bool is_not_null() const { return m_not_null; }

            /**
            * Query whether this column is UNIQUE
            * @return true if unique was called
            */
            bool is_unique() const { return m_unique; }

         private:
            std::string m_name;
            Column_Type m_type;
            bool m_primary_key = false;
            bool m_not_null = false;
            bool m_unique = false;
      };

      /**
      * The name and columns of a table, used with create_table
      */
      class Table_Schema {
         public:
            /**
            * Declare a table
            * @param name the name of the table
            * @param columns the columns of the table
            */
            Table_Schema(std::string name, std::vector<Column> columns) :
                  m_name(std::move(name)), m_columns(std::move(columns)) {}

            /**
            * Only create the table if it does not already exist
            * @return reference to this
            */
            Table_Schema& if_not_exists() {
               m_if_not_exists = true;
               return *this;
            }

            /**
            * Query the table name
            * @return the name of the table
            */
            const std::string& name() const { return m_name; }

            /**
            * Query the columns of the table
            * @return the columns of the table
            */
            const std::vector<Column>& columns() const { return m_columns; }

            /**
            * Query whether creation is conditional
            * @return true if if_not_exists was called
            */
            bool is_if_not_exists() const { return m_if_not_exists; }

         private:
            std::string m_name;
            std::vector<Column> m_columns;
            bool m_if_not_exists = false;
      };

      /**
      * Create a table
      * @param schema the name and columns of the table to create
      */
      virtual void create_table(const Table_Schema& schema) = 0;

      /**
      * Count the rows modified by the most recently executed statement
      * @return the number of rows inserted, updated or deleted
      */
      virtual size_t rows_changed_by_last_statement() = 0;

      /**
      * Prepare and run a statement to completion
      * @param sql the SQL text to execute
      * @return the number of result rows which were stepped over
      */
      virtual size_t exec(std::string_view sql) { return new_statement(sql)->spin(); }

      /**
      * Query whether this database may be used from multiple threads
      * @return true if the implementation is threadsafe
      */
      virtual bool is_threadsafe() const { return false; }

      /**
      * Return true if the given name seems to be valid as the name for a table
      *
      * Default implementation accepts non-empty [a-zA-Z0-9_]
      *
      * @param table the name to check
      * @return true if the name is acceptable as a table name
      */
      virtual bool is_valid_table_name(std::string_view table) const;

      virtual ~SQL_Database() = default;
};

}  // namespace Botan

#endif
