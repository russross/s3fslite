#include <string>
#include <map>
#include <queue>
#include <vector>
#include <syslog.h>
#include <errno.h>

#include "common.h"
#include "fileinfo.h"
#include "attrcache.h"
#include "filecache.h"
#include "s3request.h"

class cmp_file {
    public:
        bool operator ()(Filecache *&a, Filecache *&b) {
            // we want older stuff sorting as higher
            return a->time_enqueued > b->time_enqueued;
        }
};

static std::map<std::string, Filecache *> open_files;
static std::priority_queue<Filecache *, std::vector<Filecache *>, cmp_file>
    queue;

Filecache::Filecache(std::string path, bool exists) {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "Filecache::new[%s]", path.c_str());
#endif

    this->path = path;
    info = NULL;
    fd = -1;
    opencount = 0;
    this->exists = exists;
    deleted = false;
    dirty_data = false;
    dirty_metadata = false;
    enqueued = false;
}

Filecache::~Filecache() {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "Filecache::delete[%s]", path.c_str());
#endif

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
        syslog(LOG_ERR, "Filecache deleted with non-zero open count");
}

Filecache *Filecache::get(std::string path, mode_t mode) {
    Filecache *res = NULL;

    if (open_files.count(path) > 0) {
        res = open_files[path];
    } else {
        res = new Filecache(path, !mode);
        open_files[path] = res;
    }

    if (res->enqueued)
        res->resurrected = true;

    return res;
}

void Filecache::release() {
    if (!opencount && !enqueued) {
        // queue this up for flushing
        enqueued = true;
        resurrected = false;
        time_enqueued = time(NULL);

        queue.push(this);
    }
}

Filecache *Filecache::from_queue() {
    time_t now = time(NULL);

    while (queue.size()) {
        Filecache *file = queue.top();
        queue.pop();
        open_files.erase(file->path);

        // was this accessed after being put in the queue?
        if (file->resurrected) {
            file->resurrected = false;

            if (file->opencount) {
#ifdef DEBUG_CACHE
            syslog(LOG_INFO, "Filecache::from_queue resurrecting open file[%s]",
                    file->path.c_str());
#endif

                // if it is open, don't put it back in the queue
                file->enqueued = false;
                open_files[file->path] = file;
                continue;
            } else {
#ifdef DEBUG_CACHE
            syslog(LOG_INFO, "Filecache::from_queue resurrecting file[%s]",
                    file->path.c_str());
#endif

                // it's not open, so put it back with a new timestamp
                file->time_enqueued = now;
                queue.push(file);
                open_files[file->path] = file;
                continue;
            }
        }

        if (now - file->time_enqueued >= CACHE_TIMEOUT) {
            // return it with the lock held
#ifdef DEBUG_CACHE
            syslog(LOG_INFO, "Filecache::from_queue expiring[%s]",
                    file->path.c_str());
#endif
            return file;
        }

        // otherwise, it isn't old enough yet
        queue.push(file);
        open_files[file->path] = file;
        break;
    }

    return NULL;
}

void Filecache::fsync() {
#ifdef DEBUG_CACHE
    syslog(LOG_INFO, "Filecache::fsync[%s]", path.c_str());
#endif

    // new file that was deleted before it was ever transmitted
    if (!exists && deleted) {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "fsync: !exists && deleted");
#endif

        // this is what caching is all about
    }

    // deleted file: clear the cache and remove it from the server
    else if (deleted) {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "fsync: deleted");
#endif

        attrcache->del(path);
        S3request::remove(path);
        exists = false;
    }

    // new file, or one that has changed: in either case transmit it
    else if (!exists || dirty_data) {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "fsync: !exists || dirty_data");
#endif

        // does this file have contents to be transmitted?
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) < 0)
                throw -errno;

            // grab the size from the local copy
            info->size = st.st_size;
        } else {
            info->size = 0;
        }

        // clear the old entry from the cache, then update
        attrcache->del(path);
        S3request::put_file(info, fd);
        attrcache->set(info);

        exists = true;
        dirty_data = false;
        dirty_metadata = false;
    }

    // old file with metadata-only updates
    else if (dirty_metadata) {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "fsync: dirty_metadata");
#endif

        // special case: for the root, just update the cache
        if (path == "/") {
            attrcache->del(path);
            attrcache->set(info);

            return;
        }

        // clear the old entry from the cache, then update
        attrcache->del(path);
        S3request::set_fileinfo(path, info);
        attrcache->set(info);

        dirty_metadata = false;
    }

    // not new, not deleted, not updated; this is easy...
}

void Filecache::sync() {
#ifdef DEBUG_CACHE
    syslog(LOG_INFO, "Filecache::sync all");
#endif

    for (std::map<std::string, Filecache *>::iterator
            it = open_files.begin();
            it != open_files.end();
            it++)
    {
        it->second->fsync();
    }
}

// return true if any files are currently open with the given prefix
bool Filecache::openfiles(std::string prefix) {
#ifdef DEBUG_CACHE
    syslog(LOG_INFO, "Filecache::openfiles checking for prefix[%s]",
            prefix.c_str());
#endif

    for (std::map<std::string, Filecache *>::iterator
            it = open_files.begin();
            it != open_files.end();
            it++)
    {
        Filecache *file = it->second;
        if (file->path.length() >= prefix.length() &&
                file->path.compare(0, prefix.length(), prefix) == 0 &&
                file->opencount > 0)
        {
            return true;
        }
    }

    return false;
}

// the loop for the cache flushing thread
void *flush_loop(void *param) {
    pthread_mutex_lock(&global_lock);

    // once we get the lock, we hold on to it until the queue is clear
    // this prevents other transactions from happening, which prevents
    // the backlog from getting too big.  we only release the lock when
    // we are ready to sleep
    while (!flush_shutdown) {
        Filecache *file = Filecache::from_queue();
        if (file) {
            file->fsync();
            file->release();
            delete file;
        } else {
            pthread_mutex_unlock(&global_lock);
            sleep(1);
            pthread_mutex_lock(&global_lock);
        }
    }

    // sync everything when shutting down
    Filecache::sync();

    pthread_mutex_unlock(&global_lock);

    return NULL;
}
