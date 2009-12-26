#include <string>
#include <map>
#include <queue>
#include <vector>
#include <syslog.h>
#include <pthread.h>

#include "fileinfo.h"
#include "s3request.h"
#include "openfile.h"

class cmp_file {
    public:
        bool operator ()(Openfile *&a, Openfile *&b) {
            // we want older stuff sorting as higher
            return a->time_enqueued > b->time_enqueued;
        }
};

std::map<std::string, Openfile *> open_files;
std::priority_queue<Openfile *, std::vector<Openfile *>, cmp_file> queue;

pthread_mutex_t openfile_lock;

Openfile::Openfile(std::string path, bool newfile) {
    pthread_mutex_init(&lock, NULL);

    this->path = path;
    info = NULL;
    fd = -1;
    opencount = 0;
    this->newfile = newfile;
    deleted = false;
    dirty_data = false;
    dirty_metadata = false;
    enqueued = false;
}

Openfile::~Openfile() {
    if (info) {
        delete info;
        info = NULL;
    }
    if (fd >= 0) {
        // ignore any error, because throwing exceptions
        // from within dtor is frowned upon
        close(fd);
        fd = -1;
    }
    if (opencount)
        syslog(LOG_ERR, "Openfile deleted with non-zero open count");

    pthread_mutex_destroy(&lock);
}

Openfile *Openfile::get(std::string path, mode_t mode) {
    pthread_mutex_lock(&openfile_lock);

    Openfile *res = NULL;

    if (open_files.count(path) > 0) {
        res = open_files[path];
    } else {
        res = new Openfile(path, !!mode);
        open_files[path] = res;
    }

    pthread_mutex_unlock(&openfile_lock);

    pthread_mutex_lock(&res->lock);

    if (res->enqueued)
        res->resurrected = true;

    return res;
}

void Openfile::release() {
    bool q = false;

    if (!opencount && !enqueued) {
        // queue this up for flushing
        enqueued = true;
        resurrected = false;
        time_enqueued = time(NULL);

        q = true;
    }

    pthread_mutex_unlock(&lock);

    if (q) {
        pthread_mutex_lock(&openfile_lock);
        queue.push(this);
        pthread_mutex_unlock(&openfile_lock);
    }
}

Openfile *Openfile::from_queue() {
    time_t now = time(NULL);

    pthread_mutex_lock(&openfile_lock);

    while (queue.size()) {
        Openfile *file = queue.top();
        queue.pop();
        open_files.erase(file->path);
        pthread_mutex_unlock(&openfile_lock);

        pthread_mutex_lock(&file->lock);

        // was this accessed after being put in the queue?
        if (file->resurrected) {
            file->resurrected = false;

            if (file->opencount) {
                // if it is open, don't put it back in the queue
                file->enqueued = false;
                pthread_mutex_unlock(&file->lock);
                pthread_mutex_lock(&openfile_lock);
                open_files[file->path] = file;
                continue;
            } else {
                // it's not open, so put it back with a new timestamp
                file->time_enqueued = now;
                pthread_mutex_unlock(&file->lock);
                pthread_mutex_lock(&openfile_lock);
                queue.push(file);
                open_files[file->path] = file;
                continue;
            }
        }

        if (now - file->time_enqueued >= CACHE_TIMEOUT) {
            // return it with the lock held
            return file;
        }

        // otherwise, it isn't old enough yet
        pthread_mutex_unlock(&file->lock);
        pthread_mutex_lock(&openfile_lock);
        queue.push(file);
        open_files[file->path] = file;
        break;
    }

    pthread_mutex_unlock(&openfile_lock);

    return NULL;
}
