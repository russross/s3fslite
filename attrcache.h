#pragma once

#include <string>
#include <unistd.h>
#include <pthread.h>
#include <sqlite3.h>

#include "fileinfo.h"

class Attrcache {
    private:
        sqlite3 *conn;
        pthread_mutex_t lock;

    public:
        Attrcache(std::string bucket, std::string prefix);
        Fileinfo *get(std::string path);
        void set(std::string path, struct stat *info, std::string etag);
        void set(Fileinfo *info);
        void del(std::string path);
        ~Attrcache();
};

class auto_lock {
    private:
        pthread_mutex_t& lock;

    public:
        auto_lock(pthread_mutex_t& lock): lock(lock) {
            pthread_mutex_lock(&lock);
        }
        ~auto_lock() {
            pthread_mutex_unlock(&lock);
        }
};
