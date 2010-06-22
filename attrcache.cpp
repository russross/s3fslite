#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <sqlite3.h>

#include "common.h"
#include "fileinfo.h"
#include "attrcache.h"

Attrcache *attrcache;

// implement a match function for sqlite
// A match B is true if A is a file in the directory B
static void dirmatch(sqlite3_context *c, int argc, sqlite3_value **argv) {
    const char *a, *b;

    b = (const char *) sqlite3_value_text(argv[0]);
    a = (const char *) sqlite3_value_text(argv[1]);

    if (in_directory(a, b))
        sqlite3_result_int(c, 1);
    else
        sqlite3_result_int(c, 0);
}

//
// SQLite attribute caching
//
Attrcache::Attrcache(std::string bucket, std::string prefix) {
    std::string name(prefix);
    if (name.size() > 0 && name[name.size() - 1] != '/')
        name += "/";
    name += bucket;
    name += ".sqlite";
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;
    int status;

    if (sqlite3_open(name.c_str(), &conn) != SQLITE_OK) {
        std::cerr << "Can't open database: " << name << ": " <<
            sqlite3_errmsg(conn) << std::endl;
        exit(-1);
    }

    // install the match function
    if (sqlite3_create_function(conn, "match", 2, SQLITE_UTF8, NULL,
                dirmatch, NULL, NULL))
    {
        std::cerr << "Can't install 'match' function: " << 
            sqlite3_errmsg(conn) << std::endl;
        exit(-1);
    }

    // create the tables if they do not already exist
    // first, the main attribute table
    status = sqlite3_get_table(conn,
        "CREATE TABLE cache (\n"
        "    path VARCHAR(256) NOT NULL,\n"
        "    uid INTEGER,\n"
        "    gid INTEGER,\n"
        "    mode INTEGER,\n"
        "    mtime INTEGER,\n"
        "    size INTEGER,\n"
        "    PRIMARY KEY (path)\n"
        ")",
        &result, &rows, &columns, &err);

    if (status == SQLITE_OK)
        sqlite3_free_table(result);
    else
        sqlite3_free(err);

    // second, the table of directories that are fully cached
    status = sqlite3_get_table(conn,
        "CREATE TABLE directories (\n"
        "    path VARCHAR(256) NOT NULL,\n"
        "    PRIMARY KEY (path)\n"
        ")",
        &result, &rows, &columns, &err);

    if (status == SQLITE_OK)
        sqlite3_free_table(result);
    else
        sqlite3_free(err);

    // reset the list of directories known to be fully cached?
    if (dir_cache_reset == "false")
        return;

    query = sqlite3_mprintf("DELETE FROM directories");
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "error resetting directory cache: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

Attrcache::~Attrcache() {
    sqlite3_close(conn);
}

Fileinfo *Attrcache::get(std::string path) {
    char **data;
    int rows;
    int columns;
    char *err;
    char *query;

    // perform the query
    query = sqlite3_mprintf(
        "SELECT uid, gid, mode, mtime, size FROM cache WHERE path = '%q'",
        path.c_str());
    int status = sqlite3_get_table(conn, query, &data, &rows, &columns, &err);
    sqlite3_free(query);

    // error?
    if (status != SQLITE_OK) {
        syslog(LOG_ERR, "sqlite error[%s]", err);
        sqlite3_free(err);
        return NULL;
    }

    // no results?
    if (rows == 0) {
        sqlite3_free_table(data);
        return NULL;
    }

    // get the data from the second row
    Fileinfo *result = new Fileinfo(
            path,
            num(data[5]), // uid
            num(data[6]), // gid
            num(data[7]), // mode
            num(data[8]), // mtime
            num(data[9])); // size
    sqlite3_free_table(data);

    return result;
}

void Attrcache::set(std::string path, struct stat *info) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    // make sure there isn't an existing entry
    del(path);

    query = sqlite3_mprintf(
        "INSERT INTO cache (path, uid, gid, mode, mtime, size)\n"
        "VALUES ('%q', '%u', '%u', '%u', '%u', '%llu')",
        path.c_str(),
        info->st_uid,
        info->st_gid,
        info->st_mode,
        info->st_mtime,
        info->st_size);
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "set_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

void Attrcache::set(Fileinfo *info) {
    struct stat attr;
    info->toStat(&attr);
    set(info->path, &attr);
}

void Attrcache::del(std::string path) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    query = sqlite3_mprintf(
        "DELETE FROM cache WHERE path = '%q'",
        path.c_str());
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "delete_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

bool Attrcache::getdir(std::string path) {
    char **data;
    int rows;
    int columns;
    char *err;
    char *query;

    // perform the query
    query = sqlite3_mprintf(
        "SELECT path FROM directories WHERE path = '%q'",
        path.c_str());
    int status = sqlite3_get_table(conn, query, &data, &rows, &columns, &err);
    sqlite3_free(query);

    // error?
    if (status != SQLITE_OK) {
        syslog(LOG_ERR, "sqlite error[%s]", err);
        sqlite3_free(err);
        return false;
    }

    // no results?
    if (rows == 0) {
        sqlite3_free_table(data);
        return false;
    }

    sqlite3_free_table(data);
    return true;
}

void Attrcache::setdir(std::string path) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    // make sure there isn't an existing entry
    deldir(path);

    query = sqlite3_mprintf(
        "INSERT INTO directories (path)\n"
        "VALUES ('%q')",
        path.c_str());
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "set_directory error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

void Attrcache::setdir(Fileinfo *info) {
    setdir(info->path);
}

void Attrcache::deldir(std::string path) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    query = sqlite3_mprintf(
        "DELETE FROM directories WHERE path = '%q'",
        path.c_str());
    if (sqlite3_get_table(conn, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "delete_directory error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

void Attrcache::readdir(std::string path, stringlist &list) {
    char **data;
    int rows;
    int columns;
    char *err;
    char *query;

    int prefixlen = path.size() + 1;

    query = sqlite3_mprintf(
        "SELECT path FROM cache WHERE path MATCH '%q'",
        path.c_str());
    if (sqlite3_get_table(conn, query, &data, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        for (int i = 1; i <= rows; i++)
            list.push_back(&data[i][prefixlen]);

        sqlite3_free_table(data);
    } else {
        std::cerr << "read_directory error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}
