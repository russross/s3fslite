#pragma once

#include <string>
#include <map>
#include <queue>
#include <vector>
#include <pthread.h>

#define CACHE_TIMEOUT 5

class Openfile {
    public:
        pthread_mutex_t lock;

        std::string path;
        Fileinfo *info;
        int fd;
        unsigned opencount;

        bool newfile;
        bool deleted;
        bool dirty_data;
        bool dirty_metadata;
        bool enqueued;
        bool resurrected;

        time_t time_enqueued;

        Openfile(std::string path, bool newfile = false);
        ~Openfile();

        static Openfile *get(std::string path, mode_t mode = 0);
        void release();
        static Openfile *from_queue();
};
