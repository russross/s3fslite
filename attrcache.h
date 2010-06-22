#pragma once

#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>

#include "common.h"
#include "fileinfo.h"

class Attrcache {
    private:
        sqlite3 *conn;

    public:
        Attrcache(std::string bucket, std::string prefix);

        // file attributes
        Fileinfo *get(std::string path);
        void set(std::string path, struct stat *info);
        void set(Fileinfo *info);
        void del(std::string path);

        // directories for which every file is cached
        bool getdir(std::string path);
        void setdir(std::string path);
        void setdir(Fileinfo *info);
        void deldir(std::string path);
        void readdir(std::string path, stringlist &list);

        ~Attrcache();
};

extern Attrcache *attrcache;
