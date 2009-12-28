/*
 * s3fslite - Amazon S3 file system
 *
 * Copyright 2009 Russ Ross <russ@russross.com>
 *
 * Based on s3fs
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#define FUSE_USE_VERSION 26

// C++ standard library
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

// C and Unix libraries
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <pthread.h>

// FUSE
#include <fuse.h>

// project dependencies
#include "common.h"
#include "fileinfo.h"
#include "attrcache.h"
#include "filecache.h"
#include "s3request.h"

// the FUSE file system operation table
struct fuse_operations s3fs_oper;

// a single operation: this handles obtaining and cleaning up basic resources
// necessary for every operation
class Transaction {
    private:
        bool havelock;

    public:
        Transaction(bool getlock = true);
        ~Transaction();

        void getExisting(std::string path);
        void getNew(std::string path, mode_t mode);
        void getPair(std::string source, std::string target);
        void getFd();

        std::string path;
        Filecache *file;
        Filecache *target;
};

Transaction::Transaction(bool getlock) {
    file = NULL;
    target = NULL;
    havelock = getlock;

    // acquire the global lock
    if (getlock)
        pthread_mutex_lock(&global_lock);
}

Transaction::~Transaction() {
    if (file) {
        file->release();
        file = NULL;
    }
    if (target) {
        target->release();
        target = NULL;
    }

    // release the global lock
    if (havelock)
        pthread_mutex_unlock(&global_lock);
}

void Transaction::getExisting(std::string path) {
    this->path = path;
    file = Filecache::get(path);
    if (file->enqueued)
        file->resurrected = true;

    if (file->deleted)
        throw -ENOENT;

    // do we have the file info already?
    if (file->info)
        return;

    // need to get the metadata
    file->dirty_data = false;
    file->dirty_metadata = false;

    // first check the cache
    file->info = attrcache->get(path);
    if (file->info)
        return;

    // special case for /
    if (path == "/") {
        file->info = new Fileinfo(path, getuid(), getgid(),
                root_mode | S_IFDIR, time(NULL), 0);
    } else {
        // assume it doesn't exist to cache a negative hit
        file->exists = false;
        file->deleted = true;
        file->info = S3request::get_fileinfo(path);

        // oh.. it must exist
        file->exists = true;
        file->deleted = false;
    }

    // update the cache
    // the fake "/" entry is cached, too, so that rsync can update it
    attrcache->set(file->info);
}

void Transaction::getNew(std::string path, mode_t mode) {
    this->path = path;
    file = Filecache::get(path, mode);
    if (file->enqueued)
        file->resurrected = true;

    // Hmm.. still some possible race conditions here?
    // FUSE seems to do a getattr before doing a mknod or mkdir,
    // but I don't know if it handles races like:
    //
    // A: getattr         mknod
    // B:         getattr       mknod
    //
    // The cache will make them unlikely to get through, but we
    // don't catch them in all cases

    // do we have the file info already?
    if (file->info) {
        if (!file->deleted)
            throw -EEXIST;
    } else {
        file->info = new Fileinfo(path, getuid(), getgid(),
                mode, time(NULL), 0);
    }

    file->exists = false;
    file->deleted = false;
    file->dirty_data = true;
    file->dirty_metadata = true;
}

void Transaction::getPair(std::string src, std::string tgt) {
    // no renaming or linking the root
    if (src == "/" || tgt == "/")
        throw -ENOTSUP;

    path = src;
    file = Filecache::get(src);
    target = Filecache::get(tgt);

    // fail if either file is currently open
    if (file->opencount > 0 || target->opencount > 0)
        throw -EBUSY;

    if (file->enqueued)
        file->resurrected = true;
    if (target->enqueued)
        target->resurrected = true;

    if (file->deleted)
        throw -ENOENT;

    // get the source file info
    if (!file->info) {
        // need to get the metadata
        file->dirty_data = false;
        file->dirty_metadata = false;

        // first check the cache
        file->info = attrcache->get(path);
        if (file->info)
            return;

        // assume it doesn't exist to cache negative hits
        file->exists = false;
        file->deleted = true;
        file->info = S3request::get_fileinfo(src);

        // it does exist after all
        file->exists = true;
        file->deleted = false;

        // update the cache
        // the fake "/" entry is cached, too, so that rsync can update it
        attrcache->set(file->info);
    }

    // throw away the target if it exists
    if (target->info) {
        delete target->info;
        target->info = NULL;
    }

    target->deleted = true;

    if (target->fd >= 0) {
        close(target->fd);
        target->fd = -1;
    }
}

void Transaction::getFd() {
    if (file->fd >= 0)
        return;

    // why download a zero-length file?
    if (file->info->size == 0 || !file->exists)
        file->fd = create_tempfile();
    else
        file->fd = S3request::get_file(path, file->info);
}


//
//
// VFS calls
//
//


int s3fs_getattr(const char *path, struct stat *stbuf) {
#ifdef DEBUG
    syslog(LOG_INFO, "getattr[%s]", path);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        if (t.file->deleted)
            throw -ENOENT;

        t.file->info->toStat(stbuf);

        return 0;
    } catch (int e) {
        if (e == -ENOENT) {
            // getattr is used to check if a file exists, so
            // getting a File Not Found error is nothing to worry about
#ifdef DEBUG
            syslog(LOG_INFO, "getattr[%s]: File not found", path);
#endif
        } else {
            syslog(LOG_INFO, "getattr[%s]: %s", path, strerror(e));
        }
        return e;
    }
}

int s3fs_open(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "open[%s] flags[0%o]", path, fi->flags);
#endif

    try {
        Transaction t;
        t.getExisting(path);
        t.getFd();

        t.file->opencount++;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "open[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_release(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "release[%s]", path);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        t.file->opencount--;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "release[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "fsync[%s]", path);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        t.file->fsync();

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "fsync[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_mknod(const char *path, mode_t mode, dev_t rdev) {
#ifdef DEBUG
    syslog(LOG_INFO, "mknod[%s] mode[0%o]", path, mode);
#endif

    // see man 2 mknod
    // If pathname already exists, or is a symbolic link,
    // this call fails with an EEXIST error.
    try {
        Transaction t;
        t.getNew(path, mode | S_IFREG);

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "mknod[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_mkdir(const char *path, mode_t mode) {
#ifdef DEBUG
    syslog(LOG_INFO, "mkdir[%s] mode[0%o]", path, mode);
#endif

    try {
        Transaction t;
        t.getNew(path, mode | S_IFDIR);

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "mkdir[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_unlink(const char *path) {
#ifdef DEBUG
    syslog(LOG_INFO, "unlink[%s]", path);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        t.file->deleted = true;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "unlink[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_rmdir(const char *path) {
#ifdef DEBUG
    syslog(LOG_INFO, "rmdir[%s]", path);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        // sync any deleted files inside this directory
        Filecache::sync();

        // make sure the directory is empty
        std::string marker;
        stringlist entries;
        S3request::get_directory(path, marker, entries, 1);
        if (entries.size() > 0)
            throw -ENOTEMPTY;

        t.file->deleted = true;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "rmdir[%s]: %s", path, strerror(e));
        return e;
    }
}

Filecache *rename_file(std::string from, std::string to, bool toplevel) {
    Transaction t(false);

    // note: getPair sets source info, clears target info and fd
    t.getPair(from, to);

    bool isdir = t.file->info->mode & S_IFDIR;

    // if it is a directory with open files, fail
    if (toplevel && isdir && Filecache::openfiles(from + "/"))
        throw -EBUSY;

    // move the metadata over
    t.target->info = t.file->info;
    t.target->info->path = to;

    t.file->info = NULL;

    if (isdir && t.file->fd >= 0) {
        syslog(LOG_ERR, "s3fs_rename: directory with open fd");
        throw -EIO;
    }

    // if we have the file locally, move it locally
    if (t.file->fd >= 0) {
        t.target->fd = t.file->fd;
        t.file->fd = -1;

        t.target->exists = false;
        t.target->deleted = false;
        t.target->dirty_data = true;
        t.target->dirty_metadata = true;
    }

    // if we don't have the file locally, move it remotely
    else {
        // make sure the attr cache reflects what is on the server
        attrcache->del(from);
        S3request::set_fileinfo(from, t.target->info);
        attrcache->set(t.target->info);

        t.target->exists = true;
        t.target->deleted = false;
        t.target->dirty_data = false;
        t.target->dirty_metadata = false;
    }

    if (toplevel && isdir) {
        // defer deleting the source until all descendents are moved
        Filecache *source = t.file;

        // detach it from the transaction so it is not released
        t.file = NULL;

        return source;
    } else {
        // delete the source now
        t.file->deleted = true;
        return NULL;
    }
}

int s3fs_rename(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "rename[%s] -> [%s]", from, to);
#endif

    try {
        Transaction t;

        // move the file over
        t.path = from;

        // if the file is a directory, rename_file will return the
        // Filecache object for the source so we can delete it at the end
        // we are responsible for releasing it, so hand it to our transaction
        t.file = rename_file(from, to, true);

        if (t.file) {
            // this is a directory, so rename all descendents
            Filecache::sync();

            std::string marker;
            bool moretocome = true;

            while (moretocome) {
                stringlist entries;
                moretocome = S3request::get_directory(from, marker, entries,
                        MAX_KEYS_PER_DIR_REQUEST, true);

                for (size_t i = 0; i < entries.size(); i++) {
                    std::string src(from);
                    src += "/" + entries[i];
                    std::string tgt(to);
                    tgt += "/" + entries[i];

#ifdef DEBUG
                    syslog(LOG_INFO, "rename[%s] -> [%s]",
                            src.c_str(), tgt.c_str());
#endif

                    // move the file over
                    rename_file(src, tgt, false);
                }
            }

            // move any files inside the directory before removing the source
            t.file->deleted = true;

            Filecache::sync();
        }

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "rename[%s] -> [%s]: %s", from, to, strerror(e));
        return e;
    }
}

int s3fs_link(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "link[%s] -> [%s]", from, to);
#endif

    try {
        Transaction t;

        // note: getPair sets source info, clears target info and fd
        t.getPair(from, to);

        // no linking directories
        if (t.file->info->mode & S_IFDIR)
            throw -ENOTSUP;

        // copy the metadata over
        t.target->info = new Fileinfo(*t.file->info);

        // if we have the file locally, dup the fd to link them locally
        if (t.file->fd >= 0) {
            t.target->fd = dup(t.file->fd);

            t.target->exists = false;
            t.target->deleted = false;
            t.target->dirty_data = true;
            t.target->dirty_metadata = true;
        }

        // if we don't have the file locally, copy it remotely
        else {
            // make sure the attr cache reflects what is on the server
            t.target->info->path = to;
            S3request::set_fileinfo(from, t.target->info);
            attrcache->set(t.target->info);

            t.target->exists = true;
            t.target->deleted = false;
            t.target->dirty_data = false;
            t.target->dirty_metadata = false;
        }

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "link[%s] -> [%s]: %s", to, from, strerror(e));
        return e;
    }
}

int s3fs_symlink(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "symlink[%s] -> [%s]", to, from);
#endif

    try {
        Transaction t;
        t.getNew(to, S_IFLNK);
        t.getFd();

        // put the link target into a file
        if (pwrite(t.file->fd, from, strlen(from), 0) < 0)
            throw -errno;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "symlink[%s] -> [%s]: %s", to, from, strerror(e));
        return e;
    }
}

int s3fs_readlink(const char *path, char *buf, size_t size) {
#ifdef DEBUG
    syslog(LOG_INFO, "readlink[%s]", path);
#endif

    // save room for null at the end
    size--;
    if (size <= 0)
        return 0;

    try {
        Transaction t;
        t.getExisting(path);
        t.getFd();

        struct stat st;
        if (fstat(t.file->fd, &st) < 0)
            throw -errno;

        if ((size_t) st.st_size < size)
            size = st.st_size;

        if (pread(t.file->fd, buf, size, 0) < 0)
            throw -errno;

        buf[size] = 0;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "readlink[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_chmod(const char *path, mode_t mode) {
#ifdef DEBUG
    syslog(LOG_INFO, "chmod[%s] mode[0%o]", path, mode);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        // make sure we have a file type
        if (!(mode & S_IFMT))
            mode |= (t.file->info->mode & S_IFMT);

        if (t.file->info->mode != mode) {
            t.file->info->mode = mode;
            t.file->dirty_metadata = true;
        }

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "chmod[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_chown(const char *path, uid_t uid, gid_t gid) {
#ifdef DEBUG
    syslog(LOG_INFO, "chown[%s] uid[%d] gid[%d]", path, uid, gid);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        // uid or gid < 0 indicates no change
        if ((int) uid >= 0 && t.file->info->uid != uid) {
            t.file->info->uid = uid;
            t.file->dirty_metadata = true;
        }
        if ((int) gid >= 0 && t.file->info->gid != gid) {
            t.file->info->gid = gid;
            t.file->dirty_metadata = true;
        }

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "chown[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_utimens(const char *path, const struct timespec ts[2]) {
#ifdef DEBUG
    syslog(LOG_INFO, "utimens[%s] mtime[%ld]", path, ts[1].tv_sec);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        if (t.file->info->mtime != ts[1].tv_sec) {
            t.file->info->mtime = ts[1].tv_sec;
            t.file->dirty_metadata = true;
        }

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "utimens[%s]: %s", path, strerror(e));
        return e;
    }
}


int s3fs_truncate(const char *path, off_t size) {
#ifdef DEBUG
    syslog(LOG_INFO, "truncate[%s] size[%llu]", path,
            (unsigned long long) size);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        // the easy case
        if ((size_t) size == t.file->info->size)
            return 0;

        // we don't have it locally
        if (size == 0)
            t.file->info->size = 0;

        // this will only download if we don't have it and size > 0
        t.getFd();

        if (ftruncate(t.file->fd, size) < 0)
            throw -errno;

        t.file->info->mtime = time(NULL);
        t.file->dirty_data = true;
        t.file->dirty_metadata = true;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "truncate[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_read(const char *path, char *buf,
        size_t size, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "read[%s] size[%u] offset[%llu]",
            path, (unsigned) size, (unsigned long long) offset);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        int res = pread(t.file->fd, buf, size, offset);
        if (res < 0)
            throw -errno;

        return res;
    } catch (int e) {
        syslog(LOG_INFO, "read[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_write(const char *path, const char *buf,
        size_t size, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "write[%s] size[%u] offset[%llu]",
            path, (unsigned) size, (unsigned long long) offset);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        int res = pwrite(t.file->fd, buf, size, offset);
        if (res < 0)
            throw -errno;

        t.file->dirty_data = true;

        return res;
    } catch (int e) {
        syslog(LOG_INFO, "write[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_readdir(const char *path, void *buf,
        fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
#ifdef DEBUG
    syslog(LOG_INFO, "readdir[%s] offset[%llu]",
            path, (unsigned long long) offset);
#endif

    try {
        Transaction t;
        t.getExisting(path);

        // sync everything inside the directory
        Filecache::sync();

        filler(buf, ".", 0, 0);
        filler(buf, "..", 0, 0);

        std::string marker;
        bool moretocome = true;

        while (moretocome) {
            stringlist entries;
            moretocome = S3request::get_directory(path, marker, entries,
                    MAX_KEYS_PER_DIR_REQUEST);

            for (size_t i = 0; i < entries.size(); i++) {
                if (filler(buf, entries[i].c_str(), 0, 0)) {
                    syslog(LOG_ERR, "readdir: buffer full");
                    break;
                }
            }
        }

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "readdir[%s]: %s", path, strerror(e));
        return e;
    }
}

void *s3fs_init(struct fuse_conn_info *conn) {
    syslog(LOG_INFO, "init[%s]", bucket.c_str());

    // global lock
    pthread_mutex_init(&global_lock, NULL);

    // openssl
    curl_global_init(CURL_GLOBAL_ALL);

    flush_shutdown = false;
    pthread_create(&flush_thread, NULL,
            (void *(*)(void *)) flush_loop, (void *) NULL);

    return 0;
}

int s3fs_statfs(const char *path, struct statvfs *stbuf) {
#ifdef DEBUG
    syslog(LOG_INFO, "statfs[%s]", path);
#endif

    // 256T
    stbuf->f_bsize = 0X1000000;
    stbuf->f_blocks = 0X1000000;
    stbuf->f_bfree = 0x1000000;
    stbuf->f_bavail = 0x1000000;

    return 0;
}


void s3fs_destroy(void*) {
    syslog(LOG_INFO, "destroy[%s]", bucket.c_str());

    flush_shutdown = true;
    pthread_join(flush_thread, NULL);

    curl_global_cleanup();
    pthread_mutex_destroy(&global_lock);
}

int my_fuse_opt_proc(void *data, const char *arg,
        int key, struct fuse_args *outargs)
{
    if (key == FUSE_OPT_KEY_NONOPT) {
        if (bucket.size() == 0) {
            bucket = arg;
            return 0;
        } else {
            struct stat buf;
            // its the mountpoint... what is its mode?
            if (stat(arg, &buf) != -1) {
                root_mode = buf.st_mode;
            }
        }
    }
    if (key == FUSE_OPT_KEY_OPT) {
        if (strstr(arg, "accessKeyId=") != 0) {
            AWSAccessKeyId = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "secretAccessKey=") != 0) {
            AWSSecretAccessKey = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "default_acl=") != 0) {
            default_acl = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "retries=") != 0) {
            retries = atoi(strchr(arg, '=') + 1);
            return 0;
        }
        if (strstr(arg, "connect_timeout=") != 0) {
            connect_timeout = num(strchr(arg, '=') + 1);
            return 0;
        }
        if (strstr(arg, "readwrite_timeout=") != 0) {
            readwrite_timeout = num(strchr(arg, '=') + 1);
            return 0;
        }
        if (strstr(arg, "url=") != 0) {
            host = strchr(arg, '=') + 1;
            return 0;
        }
        if (strstr(arg, "attr_cache=") != 0) {
            attr_cache = strchr(arg, '=') + 1;
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    bzero(&s3fs_oper, sizeof(s3fs_oper));

    struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc);

    if (bucket.size() == 0) {
        std::cout << argv[0] << ": " << "missing bucket" << std::endl;
        exit(1);
    }

    if (AWSSecretAccessKey.size() == 0) {
        std::string line;
        std::ifstream passwd("/etc/passwd-s3fs");
        while (getline(passwd, line)) {
            if (line[0]=='#')
                continue;
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                // is accessKeyId missing?
                if (AWSAccessKeyId.size() == 0)
                    AWSAccessKeyId = line.substr(0, pos);
                // is secretAccessKey missing?
                if (AWSSecretAccessKey.size() == 0) {
                    if (line.substr(0, pos) == AWSAccessKeyId)
                        AWSSecretAccessKey =
                            line.substr(pos + 1, std::string::npos);
                }
            }
        }
    }

    if (AWSAccessKeyId.size() == 0) {
        std::cout << argv[0] << ": " << "missing accessKeyId.. see "
            "/etc/passwd-s3fs or use, e.g., -o accessKeyId=aaa" << std::endl;
        exit(1);
    }
    if (AWSSecretAccessKey.size() == 0) {
        std::cout << argv[0] << ": " << "missing secretAccessKey... see "
            "/etc/passwd-s3fs or use, e.g., -o secretAccessKey=bbb" <<
            std::endl;
        exit(1);
    }

    s3fs_oper.getattr = s3fs_getattr;
    s3fs_oper.readlink = s3fs_readlink;
    s3fs_oper.mknod = s3fs_mknod;
    s3fs_oper.mkdir = s3fs_mkdir;
    s3fs_oper.unlink = s3fs_unlink;
    s3fs_oper.rmdir = s3fs_rmdir;
    s3fs_oper.symlink = s3fs_symlink;
    s3fs_oper.rename = s3fs_rename;
    s3fs_oper.link = s3fs_link;
    s3fs_oper.chmod = s3fs_chmod;
    s3fs_oper.chown = s3fs_chown;
    s3fs_oper.truncate = s3fs_truncate;
    s3fs_oper.open = s3fs_open;
    s3fs_oper.read = s3fs_read;
    s3fs_oper.write = s3fs_write;
    s3fs_oper.statfs = s3fs_statfs;
    s3fs_oper.release = s3fs_release;
    s3fs_oper.fsync = s3fs_fsync;
    s3fs_oper.readdir = s3fs_readdir;
    s3fs_oper.init = s3fs_init;
    s3fs_oper.destroy = s3fs_destroy;
    s3fs_oper.utimens = s3fs_utimens;

    // load the list of mime types
    std::string line;
    std::ifstream passwd("/etc/mime.types");
    while (getline(passwd, line)) {
        if (line[0] == '#')
            continue;
        std::stringstream tmp(line);
        std::string mimeType;
        tmp >> mimeType;
        while (tmp) {
            std::string ext;
            tmp >> ext;
            if (ext.size() == 0)
                continue;
            mimeTypes[ext] = mimeType;
        }
    }

    attrcache = new Attrcache(bucket, attr_cache);

    int status =
        fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);

    delete attrcache;
    return status;
}
