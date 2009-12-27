#pragma once

#include <string>
#include <unistd.h>
#include <sqlite3.h>

#include "fileinfo.h"

class Attrcache {
    private:
        sqlite3 *conn;

    public:
        Attrcache(std::string bucket, std::string prefix);
        Fileinfo *get(std::string path);
        void set(std::string path, struct stat *info, std::string etag);
        void set(Fileinfo *info);
        void del(std::string path);
        ~Attrcache();
};

extern Attrcache *attrcache;
