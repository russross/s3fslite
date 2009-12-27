#include <string>
#include <map>
#include <queue>
#include <vector>
#include <syslog.h>
#include <errno.h>

#include "fileinfo.h"
#include "attrcache.h"
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

Openfile::Openfile(std::string path, bool exists) {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "Openfile::new[%s]", path.c_str());
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

Openfile::~Openfile() {
#ifdef DEBUG_CACHE
        syslog(LOG_INFO, "Openfile::delete[%s]", path.c_str());
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
        syslog(LOG_ERR, "Openfile deleted with non-zero open count");
}

Openfile *Openfile::get(std::string path, mode_t mode) {
    Openfile *res = NULL;

    if (open_files.count(path) > 0) {
        res = open_files[path];
    } else {
        res = new Openfile(path, !mode);
        open_files[path] = res;
    }

    if (res->enqueued)
        res->resurrected = true;

    return res;
}

void Openfile::release() {
    if (!opencount && !enqueued) {
        // queue this up for flushing
        enqueued = true;
        resurrected = false;
        time_enqueued = time(NULL);

        queue.push(this);
    }
}

Openfile *Openfile::from_queue() {
    time_t now = time(NULL);

    while (queue.size()) {
        Openfile *file = queue.top();
        queue.pop();
        open_files.erase(file->path);

        // was this accessed after being put in the queue?
        if (file->resurrected) {
            file->resurrected = false;

            if (file->opencount) {
#ifdef DEBUG_CACHE
            syslog(LOG_INFO, "Openfile::from_queue resurrecting open file[%s]",
                    file->path.c_str());
#endif

                // if it is open, don't put it back in the queue
                file->enqueued = false;
                open_files[file->path] = file;
                continue;
            } else {
#ifdef DEBUG_CACHE
            syslog(LOG_INFO, "Openfile::from_queue resurrecting file[%s]",
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
            syslog(LOG_INFO, "Openfile::from_queue expiring[%s]",
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

void Openfile::fsync() {
#ifdef DEBUG_CACHE
    syslog(LOG_INFO, "Openfile::fsync[%s]", path.c_str());
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

void Openfile::sync() {
#ifdef DEBUG_CACHE
    syslog(LOG_INFO, "Openfile::sync all");
#endif

    for (std::map<std::string, Openfile *>::iterator
            it = open_files.begin();
            it != open_files.end();
            it++)
    {
        it->second->fsync();
    }
}
