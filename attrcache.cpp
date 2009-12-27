#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <sqlite3.h>

#include "fileinfo.h"
#include "attrcache.h"

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
    int status;

    if (sqlite3_open(name.c_str(), &conn) != SQLITE_OK) {
        std::cerr << "Can't open database: " << name << ": " <<
            sqlite3_errmsg(conn) << std::endl;
        exit(-1);
    }

    // create the table if it does not already exist
    status = sqlite3_get_table(conn,
        "CREATE TABLE cache (\n"
        "    path VARCHAR(256) NOT NULL,\n"
        "    uid INTEGER,\n"
        "    gid INTEGER,\n"
        "    mode INTEGER,\n"
        "    mtime INTEGER,\n"
        "    size INTEGER,\n"
        "    etag VARCHAR(96),\n"
        "    PRIMARY KEY (path)\n"
        ")",
        &result, &rows, &columns, &err);

    if (status == SQLITE_OK)
        sqlite3_free_table(result);
    else
        sqlite3_free(err);
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
        "SELECT uid, gid, mode, mtime, size, etag FROM cache WHERE path = '%q'",
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
            strtoul(data[6], NULL, 10), // uid
            strtoul(data[7], NULL, 10), // gid
            strtoul(data[8], NULL, 10), // mode
            strtoul(data[9], NULL, 10), // mtime
            strtoul(data[10], NULL, 10), // size
            data[11]); // etag
    sqlite3_free_table(data);

    return result;
}

void Attrcache::set(std::string path, struct stat *info, std::string etag) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    // make sure there isn't an existing entry
    del(path);

    query = sqlite3_mprintf(
        "INSERT INTO cache (path, uid, gid, mode, mtime, size, etag)\n"
        "VALUES ('%q', '%u', '%u', '%u', '%u', '%llu', '%q')",
        path.c_str(),
        info->st_uid,
        info->st_gid,
        info->st_mode,
        info->st_mtime,
        info->st_size,
        etag.c_str());
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
    set(info->path, &attr, info->etag);
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

