#pragma once

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sqlite3.h>

class Cache {
private:
    sqlite3 *db;

public:
    Cache(std::string &bucket);
    int get(std::string &path, struct stat *info);
    void set(std::string &path, struct stat *info);
    void del(std::string &path);
    ~Cache();
};
