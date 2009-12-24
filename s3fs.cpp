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
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <pthread.h>

// non-standard dependencies
#include <openssl/hmac.h>
#include <fuse.h>

// project dependencies
#include "fileinfo.h"
#include "attrcache.h"
#include "s3request.h"
#include "s3fs.h"

using namespace std;

// config parameters
string bucket;
string AWSAccessKeyId;
string AWSSecretAccessKey;
string host("http://s3.amazonaws.com");
mode_t root_mode = 0755;
string attr_cache;
int retries = 2;
long connect_timeout = 2;
time_t readwrite_timeout = 10;

// private, public-read, public-read-write, authenticated-read
string default_acl;
string private_acl("private");
string public_acl("public-read");

Attrcache *attrcache;

pthread_mutex_t *mutex_buf = NULL;

mimes_t mimeTypes;

// fd -> flags
map<int, int> s3fs_descriptors;
pthread_mutex_t s3fs_descriptors_lock;
static std::string SPACES(" \t\r\n");
static std::string QUOTES("\"");

std::string trim_spaces(const std::string &s) {
    string::size_type start(s.find_first_not_of(SPACES));
    string::size_type end(s.find_last_not_of(SPACES));
    if (start == string::npos || end == string::npos)
        return "";
    return s.substr(start, end + 1 - start);
}

std::string trim_quotes(const std::string &s) {
    string::size_type start(s.find_first_not_of(QUOTES));
    string::size_type end(s.find_last_not_of(QUOTES));
    if (start == string::npos || end == string::npos)
        return "";
    return s.substr(start, end + 1 - start);
}

int get_flags(int fd) {
    auto_lock lock(s3fs_descriptors_lock);
    return s3fs_descriptors[fd];
}

class Transaction {
    public:
        Transaction(std::string path, mode_t mode = 0);
        ~Transaction();

        std::string path;
        Fileinfo *info;
        int fd;
};

Transaction::Transaction(std::string path, mode_t mode) {
    this->path = path;
    fd = -1;

    // is this for a new or existing file?
    if (mode) {
        info = new Fileinfo(path, getuid(), getgid(),
                mode, time(NULL), 0, MD5_EMPTY);
    } else {
        // first check the cache
        info = attrcache->get(path);
        if (info)
            return;

        // special case for /
        if (path == "/") {
            info = new Fileinfo(path, getuid(), getgid(),
                    root_mode | S_IFDIR, time(NULL), 0, MD5_EMPTY);
        } else {
            info = S3request::get_fileinfo(path);
        }

        // update the cache
        // the fake "/" entry is cached, too, so that rsync can update it
        attrcache->set(info);
    }
}

Transaction::~Transaction() {
    delete info;
    info = NULL;

    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

// copy a file, possibly onto itself (to update headers)
void generic_copy_file(Transaction *t) {
    // special case: for the root, just update the cache
    if (t->path == "/") {
        attrcache->del(t->path);
        attrcache->set(t->info);
        return;
    }

    attrcache->del(t->path);

    S3request::set_fileinfo(t->path, t->info);

    // put the new name in the cache
    attrcache->set(t->info);
}

// create a new file/directory
void generic_put(Transaction *t, int fd = -1) {
    // does this file have contents to be transmitted?
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) < 0)
            throw -errno;

        // grab the size from the cached file
        t->info->size = st.st_size;
    }

    attrcache->del(t->path);
    S3request::put_file(t->info, fd);
    attrcache->set(t->info);
}

// remove a file or directory
void generic_remove(Transaction *t) {
    attrcache->del(t->path);
    S3request::remove(t->path);
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
        Transaction t(path);
        t.info->toStat(stbuf);

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

int s3fs_access(const char *path, int mask) {
#ifdef DEBUG
    syslog(LOG_INFO, "access[%s] mask[0%o]", path, mask);
#endif

    // let anyone do anything
    return 0;
}

int s3fs_open(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "open[%s] flags[0%o]", path, fi->flags);
#endif

    Transaction t(path);

    // TODO: see if this file is already open
    try {
        fi->fh = S3request::get_file(t.path, t.info);

        // remember flags and headers...
        auto_lock lock(s3fs_descriptors_lock);

        s3fs_descriptors[fi->fh] = fi->flags;

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "open[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_flush(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "flush[%s]", path);
#endif

    try {
        Transaction t(path);

        int fd = fi->fh;

        // fi->flags is not available here
        int flags = get_flags(fd);

        // if it was opened with write permission, assume it has changed
        // TODO: track if file was actually changed
        if ((flags & O_RDWR) || (flags & O_WRONLY))
            generic_put(&t, fd);

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "flush[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_release(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
    syslog(LOG_INFO, "release[%s]", path);
#endif

    // TODO: should not assume flush has been called
    try {
        int fd = fi->fh;
        if (close(fd) < 0)
            throw -errno;

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
        Transaction t(path, mode | S_IFREG);
        generic_put(&t);

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
        Transaction t(path, mode | S_IFDIR);
        generic_put(&t);

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
        Transaction t(path);
        generic_remove(&t);

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
        Transaction t(path);

        // make sure the directory is empty
        string marker;
        stringlist entries;
        S3request::get_directory(path, marker, entries, 1);
        if (entries.size() > 0)
            throw -ENOTEMPTY;

        generic_remove(&t);

        return 0;
    } catch (int e) {
        syslog(LOG_INFO, "rmdir[%s]: %s", path, strerror(e));
        return e;
    }
}

int s3fs_rename(const char *from, const char *to) {
#ifdef DEBUG
    syslog(LOG_INFO, "rename[%s] -> [%s]", from, to);
#endif

    try {
        Transaction t(from);

        // no renaming directories (yet)
        if (t.info->mode & S_IFDIR)
            throw -ENOTSUP;

        t.info->path = to;
        generic_copy_file(&t);

        t.path = from;
        t.info->path = from;
        generic_remove(&t);

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
        Transaction t(from);

        // no linking directories
        if (t.info->mode & S_IFDIR)
            throw -ENOTSUP;

        t.info->path = to;
        generic_copy_file(&t);

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
        Transaction t(to, S_IFLNK);

        // create a temporary local file
        t.fd = create_tempfile();

        // put the link target into a file
        if (pwrite(t.fd, from, strlen(from), 0) < 0)
            throw -errno;

        generic_put(&t, t.fd);

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
        Transaction t(path);
        t.fd = S3request::get_file(t.path, t.info);

        struct stat st;
        if (fstat(t.fd, &st) < 0)
            throw -errno;

        if ((size_t) st.st_size < size)
            size = st.st_size;

        if (pread(t.fd, buf, size, 0) < 0)
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
        Transaction t(path);

        // make sure we have a file type
        if (!(mode & S_IFMT))
            mode |= (t.info->mode & S_IFMT);

        t.info->mode = mode;
        generic_copy_file(&t);

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
        Transaction t(path);

        // uid or gid < 0 indicates no change
        if ((int) uid >= 0)
            t.info->uid = uid;
        if ((int) gid >= 0)
            t.info->gid = gid;

        generic_copy_file(&t);

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
        Transaction t(path);

        t.info->mtime = ts[1].tv_sec;
        generic_copy_file(&t);

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
        Transaction t(path);

        // TODO: support all sizes of truncates
        if (size != 0)
            throw -ENOTSUP;

        // this is just like creating a new file of length zero,
        // but keeping the old attributes
        generic_put(&t);

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
        int res = pread(fi->fh, buf, size, offset);
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
        int res = pwrite(fi->fh, buf, size, offset);
        if (res < 0)
            throw -errno;

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
        filler(buf, ".", 0, 0);
        filler(buf, "..", 0, 0);

        string marker;
        int moretocome = 1;

        while (moretocome) {
            stringlist entries;
            moretocome = S3request::get_directory(path, marker, entries);

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

/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&mutex_buf[n]);
    } else {
        pthread_mutex_unlock(&mutex_buf[n]);
    }
}

/**
 * OpenSSL uniq id function.
 *
 * @return    thread id
 */
unsigned long id_function(void) {
    return ((unsigned long) pthread_self());
}

void *s3fs_init(struct fuse_conn_info *conn) {
    syslog(LOG_INFO, "init[%s]", bucket.c_str());

    // openssl
    mutex_buf = static_cast<pthread_mutex_t *>(
            malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t)));
    for (int i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&mutex_buf[i], NULL);
    CRYPTO_set_locking_callback(locking_function);
    CRYPTO_set_id_callback(id_function);
    curl_global_init(CURL_GLOBAL_ALL);
    pthread_mutex_init(&s3fs_descriptors_lock, NULL);

    string line;
    ifstream passwd("/etc/mime.types");
    while (getline(passwd, line)) {
        if (line[0] == '#')
            continue;
        stringstream tmp(line);
        string mimeType;
        tmp >> mimeType;
        while (tmp) {
            string ext;
            tmp >> ext;
            if (ext.size() == 0)
                continue;
            mimeTypes[ext] = mimeType;
        }
    }
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

    // openssl
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;
    curl_global_cleanup();
    pthread_mutex_destroy(&s3fs_descriptors_lock);
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
        // ### TODO: prefix
        if (strstr(arg, "retries=") != 0) {
            retries = atoi(strchr(arg, '=') + 1);
            return 0;
        }
        if (strstr(arg, "connect_timeout=") != 0) {
            connect_timeout = strtol(strchr(arg, '=') + 1, 0, 10);
            return 0;
        }
        if (strstr(arg, "readwrite_timeout=") != 0) {
            readwrite_timeout = strtoul(strchr(arg, '=') + 1, 0, 10);
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

struct fuse_operations s3fs_oper;

int main(int argc, char *argv[]) {
    bzero(&s3fs_oper, sizeof(s3fs_oper));

    struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc);

    if (bucket.size() == 0) {
        cout << argv[0] << ": " << "missing bucket" << endl;
        exit(1);
    }

    if (AWSSecretAccessKey.size() == 0) {
        string line;
        ifstream passwd("/etc/passwd-s3fs");
        while (getline(passwd, line)) {
            if (line[0]=='#')
                continue;
            size_t pos = line.find(':');
            if (pos != string::npos) {
                // is accessKeyId missing?
                if (AWSAccessKeyId.size() == 0)
                    AWSAccessKeyId = line.substr(0, pos);
                // is secretAccessKey missing?
                if (AWSSecretAccessKey.size() == 0) {
                    if (line.substr(0, pos) == AWSAccessKeyId)
                        AWSSecretAccessKey = line.substr(pos + 1, string::npos);
                }
            }
        }
    }

    if (AWSAccessKeyId.size() == 0) {
        cout << argv[0] << ": " << "missing accessKeyId.. see "
            "/etc/passwd-s3fs or use, e.g., -o accessKeyId=aaa" << endl;
        exit(1);
    }
    if (AWSSecretAccessKey.size() == 0) {
        cout << argv[0] << ": " << "missing secretAccessKey... see "
            "/etc/passwd-s3fs or use, e.g., -o secretAccessKey=bbb" << endl;
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
    s3fs_oper.flush = s3fs_flush;
    s3fs_oper.release = s3fs_release;
    s3fs_oper.fsync = s3fs_fsync;
    s3fs_oper.readdir = s3fs_readdir;
    s3fs_oper.init = s3fs_init;
    s3fs_oper.destroy = s3fs_destroy;
    s3fs_oper.utimens = s3fs_utimens;

    attrcache = new Attrcache(bucket, attr_cache);

    int status =
        fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);

    delete attrcache;
    return status;
}
