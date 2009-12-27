#pragma once

#include <string>
#include <time.h>
#include <fcntl.h>

class Fileinfo {
    public:
        std::string path;
        unsigned uid;
        unsigned gid;
        mode_t mode;
        time_t mtime;
        size_t size;

        Fileinfo(std::string path, struct stat *info);
        Fileinfo(std::string path, unsigned uid, unsigned gid,
                mode_t mode, time_t mtime, size_t size);
        void set(std::string path, unsigned uid, unsigned gid,
                mode_t mode, time_t mtime, size_t size);
        void toStat(struct stat *info);
};
