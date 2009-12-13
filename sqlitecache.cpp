#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <syslog.h>

#include "sqlitecache.h"

Cache::Cache(std::string &bucket) {
    std::string name(bucket);
    name += ".db";
    char **result;
    int rows;
    int columns;
    char *err;
    int status;

    if (sqlite3_open(name.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << name << ": " <<
            sqlite3_errmsg(db) << std::endl;
        exit(-1);
    }

    // create the table if it does not already exist
    status = sqlite3_get_table(db,
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
}

Cache::~Cache() {
    sqlite3_close(db);
}

int Cache::get(std::string &path, struct stat *info) {
    char **result;
    int rows;
    int columns;
    char *err;
    int status = 0;
    char *query;

    query = sqlite3_mprintf(
        "SELECT uid, gid, mode, mtime, size FROM cache WHERE path = '%q'",
        path.c_str());
    std::cout << "query: " << query << std::endl;
    if (sqlite3_get_table(db, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        if (rows > 0) {
            // get the data from the second row
            info->st_nlink = 1;
            info->st_uid = strtoul(result[5], NULL, 10);
            info->st_gid = strtoul(result[6], NULL, 10);
            info->st_mode = strtoul(result[7], NULL, 10);
            info->st_mtime = strtoul(result[8], NULL, 10);
            info->st_size = strtoul(result[9], NULL, 10);
            if (S_ISREG(info->st_mode))
                info->st_blocks = info->st_size / 512 + 1;
            status = 1;
        }
        sqlite3_free_table(result);
    } else {
        std::cerr << "get_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);

    return status;
}

void Cache::set(std::string &path, struct stat *info) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    // make sure there isn't an existing entry
    del(path);

    query = sqlite3_mprintf(
        "INSERT INTO cache (path, uid, gid, mode, mtime, size)\n"
        "VALUES ('%q', '%u', '%u', '%u', '%u', '%u')",
        path.c_str(),
        info->st_uid,
        info->st_gid,
        info->st_mode,
        info->st_mtime,
        info->st_size);
    if (sqlite3_get_table(db, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "set_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

void Cache::del(std::string &path) {
    char **result;
    int rows;
    int columns;
    char *err;
    char *query;

    query = sqlite3_mprintf(
        "DELETE FROM cache WHERE path = '%q'",
        path.c_str());
    if (sqlite3_get_table(db, query, &result, &rows, &columns, &err) ==
            SQLITE_OK)
    {
        sqlite3_free_table(result);
    } else {
        std::cerr << "delete_entry error: " << err << std::endl;
        sqlite3_free(err);
    }
    sqlite3_free(query);
}

int test_main() {
    std::string name("test");
    Cache db(name);

    struct stat info;

    std::string file("/foo/bar");
    info.st_uid = 1000;
    info.st_gid = 1001;
    info.st_mode = 0644;
    info.st_mtime = 12345;
    info.st_size = 42;
    db.set(file, &info);

    if (db.get(file, &info)) {
        std::cout << "info: " <<
            "uid: " << info.st_uid << std::endl <<
            "gid: " << info.st_gid << std::endl <<
            "mode: " << info.st_mode << std::endl <<
            "mtime: " << info.st_mtime << std::endl <<
            "size: " << info.st_size << std::endl;
        file = "/foo";
        db.set(file, &info);
    }

    return 0;
}
