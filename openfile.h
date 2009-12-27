#pragma once

#include <string>
#include <map>
#include <queue>
#include <vector>

#define CACHE_TIMEOUT 5

class Openfile {
    public:
        std::string path;
        Fileinfo *info;
        int fd;
        unsigned opencount;

        bool exists;
        bool deleted;
        bool dirty_data;
        bool dirty_metadata;
        bool enqueued;
        bool resurrected;

        time_t time_enqueued;

        Openfile(std::string path, bool exists = true);
        ~Openfile();

        static Openfile *get(std::string path, mode_t mode = 0);
        void release();
        static Openfile *from_queue();
        void fsync();
        static void sync();
};
