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
        std::string etag;

        Fileinfo(std::string path, struct stat *info, std::string etag);
        Fileinfo(std::string path, unsigned uid, unsigned gid,
                mode_t mode, time_t mtime, size_t size, std::string etag);
        void set(std::string path, unsigned uid, unsigned gid,
                mode_t mode, time_t mtime, size_t size, std::string etag);
        void toStat(struct stat *info);
};
