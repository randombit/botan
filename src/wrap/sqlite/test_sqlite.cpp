/*
 * Quick and dirty test for SQLite3 encryption codec.
 * (C) 2010 Olivier de Gaalon
 *
 * Distributed under the terms of the Botan license
 */

#define SQLITE_HAS_CODEC 1

#include <sqlite3.h>
#include <stdio.h>

namespace SQL
{
    const char * CREATE_TABLE_TEST = 
        "create table 'test' (id INTEGER PRIMARY KEY, name TEXT, creationtime TEXT);";
    const char * CREATE_TABLE_TEST2 = 
        "create table 'test2' (id INTEGER PRIMARY KEY, name TEXT, creationtime TEXT);";
    const char * INSERT_INTO_TEST = 
        "INSERT INTO test (name, creationtime) VALUES ('widget', '1st time');\
         INSERT INTO test (name, creationtime) VALUES ('widget', '2nd time');\
         INSERT INTO test (name, creationtime) VALUES ('widget', '3rd time');\
         INSERT INTO test (name, creationtime) VALUES ('widget', '4th time');\
         INSERT INTO test (name, creationtime) VALUES ('widget', '5th time');";
    const char * INSERT_INTO_TEST2 = 
        "INSERT INTO test2 (name, creationtime) VALUES ('widget2', '1st time2');\
         INSERT INTO test2 (name, creationtime) VALUES ('widget2', '2nd time2');\
         INSERT INTO test2 (name, creationtime) VALUES ('widget2', '3rd time2');\
         INSERT INTO test2 (name, creationtime) VALUES ('widget2', '4th time2');\
         INSERT INTO test2 (name, creationtime) VALUES ('widget2', '5th time2');";
    const char * SELECT_FROM_TEST = 
        "SELECT * FROM test;";
    const char * SELECT_FROM_TEST2 = 
        "SELECT * FROM test2;";
};

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    fprintf(stderr, "\t");
    for(i=0; i<argc; i++){
        fprintf(stderr, "%s = %s | ", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    fprintf(stderr, "\n");
    return 0;
}

int main(int argc, char** argv)
{
    sqlite3 * db;
    const char * key = "anotherkey";
    const char * dbname = "./testdb";
    int keylen = 7;
    char * error=0;

    fprintf(stderr, "Creating Database \"%s\"\n", dbname);
    int rc = sqlite3_open(dbname, &db);
    if (rc != SQLITE_OK) { fprintf(stderr, "Can't open/create database: %s\n", sqlite3_errmsg(db)); return 1; }

    fprintf(stderr, "Keying Database with key \"%s\"\n", key);
    rc = sqlite3_key(db, key, keylen);
    if (rc != SQLITE_OK) { fprintf(stderr, "Can't key database: %s\n", sqlite3_errmsg(db)); return 1; }

    fprintf(stderr, "Creating table \"test\"\n");
    rc = sqlite3_exec(db, SQL::CREATE_TABLE_TEST, 0, 0, &error);
    if (rc != SQLITE_OK) { fprintf(stderr, "SQL error: %s\n", error); return 1; }

    fprintf(stderr, "Creating table \"test2\"\n");
    rc = sqlite3_exec(db, SQL::CREATE_TABLE_TEST2, 0, 0, &error);
    if (rc != SQLITE_OK) { fprintf(stderr, "SQL error: %s\n", error); return 1; }

    fprintf(stderr, "Inserting into table \"test\"\n");
    rc = sqlite3_exec(db, SQL::INSERT_INTO_TEST, 0, 0, &error);
    if (rc != SQLITE_OK) { fprintf(stderr, "SQL error: %s\n", error); return 1; }

    fprintf(stderr, "Inserting into table \"test2\"\n");
    rc = sqlite3_exec(db, SQL::INSERT_INTO_TEST2, 0, 0, &error);
    if (rc != SQLITE_OK) { fprintf(stderr, "SQL error: %s\n", error); return 1; }

    fprintf(stderr, "Closing Database \"%s\"\n", dbname);
    sqlite3_close(db);

    fprintf(stderr, "Opening Database \"%s\"\n", dbname);
    rc = sqlite3_open(dbname, &db);
    if (rc != SQLITE_OK) { fprintf(stderr, "Can't open/create database: %s\n", sqlite3_errmsg(db)); return 1; }

    fprintf(stderr, "Keying Database with key \"%s\"\n", key);
    rc = sqlite3_key(db, key, keylen);
    if (rc != SQLITE_OK) { fprintf(stderr, "Can't key database: %s\n", sqlite3_errmsg(db)); return 1; }

    fprintf(stderr, "Selecting all from test\n");
    rc = sqlite3_exec(db, SQL::SELECT_FROM_TEST, callback, 0, &error);
    if (rc != SQLITE_OK) { fprintf(stderr, "SQL error: %s\n", error); return 1; }

    fprintf(stderr, "Selecting all from test2\n");
    rc = sqlite3_exec(db, SQL::SELECT_FROM_TEST2, callback, 0, &error);
    if (rc != SQLITE_OK) { fprintf(stderr, "SQL error: %s\n", error); return 1; }

    fprintf(stderr, "Closing Database \"%s\"\n", dbname);
    sqlite3_close(db);

    fprintf(stderr, "All Seems Good \n");
    return 0;
}
