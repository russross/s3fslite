#pragma once

#include <string>
#include <map>
#include <queue>
#include <vector>

class Filecache {
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

        Filecache(std::string path, bool exists = true);
        ~Filecache();

        static Filecache *get(std::string path, mode_t mode = 0);
        void release();
        static Filecache *from_queue();
        void fsync();
        static void sync();
        static bool openfiles(std::string prefix);
};

void *flush_loop(void *param);
